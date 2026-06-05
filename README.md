# 🌊 MAC Flooding Attack

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-required-orange)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-Educational-green)]()
[![Video Demo](https://img.shields.io/badge/Demo-YouTube-red?logo=youtube)](https://youtu.be/kFKNr5RlzAQ)

---

## 🎬 Demo

📺 [Ver video de demostración](https://youtu.be/kFKNr5RlzAQ)

---

## 📋 Descripción

Este laboratorio demuestra cómo un atacante puede **saturar la tabla CAM** de un switch mediante el envío masivo de direcciones MAC falsas. Al provocar el desbordamiento de esta tabla, el switch comienza a difundir tráfico por múltiples puertos, aumentando el riesgo de **interceptación de datos** y afectando el funcionamiento normal de la red.

---

## 🎯 Objetivos

### Objetivo del Laboratorio
Demostrar cómo el desbordamiento de la tabla CAM convierte al switch en un hub, exponiendo el tráfico de red a sniffing por parte del atacante.

### Objetivo del Script
Generar y transmitir continuamente tramas Ethernet con **direcciones MAC de origen aleatorias** para llenar la tabla CAM del switch hasta alcanzar su capacidad máxima.

---

## ⚙️ Requisitos

- Python 3.x
- Scapy (`pip install scapy`)
- Permisos root
- Switch **sin** Port Security configurado

---

## 🚀 Uso

```bash
sudo python3 Mac_Flooding.py <iface> [-c <count>] [-d <delay>]
```

### Parámetros

| Parámetro | Descripción | Obligatorio |
|-----------|-------------|:-----------:|
| `iface` | Interfaz de red del atacante (ej. `eth0`) | ✅ |
| `-c` / `--count` | Número de paquetes a enviar (`0` = infinito) | ❌ |
| `-d` / `--delay` | Retardo en segundos entre paquetes | ❌ |

### Ejemplo

```bash
sudo python3 Mac_Flooding.py ens3 -c 0 -d 0.001
```

---

## 🔄 Flujo de Ejecución

```
1. Se generan MACs de origen y destino completamente aleatorias para cada frame
2. Cada frame enviado inserta una nueva entrada en la tabla CAM del switch
3. La tabla CAM tiene capacidad limitada (típicamente 4K–16K entradas según el modelo)
4. Al llenarse, el switch no puede aprender nuevas MACs y entra en modo flooding
5. En modo flooding, el switch retransmite todos los frames a todos los puertos → sniffing
```

---

## 🛡️ Contramedidas

| Medida | Comando / Acción | Efecto |
|--------|-----------------|--------|
| Port Security | `switchport port-security maximum 1` | Limita MACs aprendidas por puerto |
| Port Security Sticky | `switchport port-security mac-address sticky` | Aprende y fija MACs dinámicamente |

---


## ⚠️ Aviso Legal

> Este proyecto es exclusivamente con fines **educativos** en un entorno controlado de laboratorio. El uso de estas técnicas fuera de entornos autorizados es ilegal y éticamente incorrecto.
