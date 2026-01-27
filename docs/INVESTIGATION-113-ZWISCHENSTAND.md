# Zwischenstand: E2E Test Issue #113 - device.Up() Blocking

**Datum:** 2026-01-26
**Status:** Investigation in Progress
**Blocker:** `device.Up()` aus wireguard-go blockiert indefinit

---

## Zusammenfassung

Die E2E-Validierung auf der Windows VM zeigt, dass das WireGuard Interface `wg-nb-machine` korrekt erstellt wird (IP: 100.95.84.14/16), aber der Service blockiert beim Aufruf von `device.Up()` aus der wireguard-go Library. Der PeerEngine kann daher nicht initialisiert werden.

---

## Aktueller Stand

### Was funktioniert
- [x] Windows Build kompiliert erfolgreich
- [x] Service installiert und startet
- [x] WireGuard Interface wird erstellt
- [x] IP-Adresse wird zugewiesen (100.95.84.14/16)
- [x] TunDevice.Create() erfolgreich

### Was NICHT funktioniert
- [ ] `device.Up()` blockiert indefinit
- [ ] PeerEngine wird nicht initialisiert
- [ ] Keine Peer-Verbindungen
- [ ] DC nicht erreichbar

---

## Root Cause Analysis

### Call Chain (device.Up())
```
TunDevice.Up() [device_windows.go:109]
  └─► device.Up() [wireguard-go device/device.go:212]
        └─► changeState(deviceStateUp) [device.go:213]
              └─► device.state.Lock() [device.go:143]
                    └─► upLocked() [device.go:156]
                          ├─► BindUpdate() [device.go:175] ← Potentieller Blocker #1
                          │     └─► closeBindLocked() [device.go:479]
                          │           └─► netc.stopping.Wait() [device.go:437] ← Potentieller Blocker #2
                          └─► ipcMutex.Lock() [device.go:182] ← Potentieller Blocker #3
```

### Identifizierte potentielle Blocker

| # | Location | Beschreibung | Wahrscheinlichkeit |
|---|----------|--------------|-------------------|
| 1 | `BindUpdate()` | Öffnet UDP Sockets, startet Receiver Routinen | Medium |
| 2 | `netc.stopping.Wait()` | Wartet auf alle vorherigen Receiver Goroutinen | Hoch |
| 3 | `ipcMutex.Lock()` | UAPI Named Pipe könnte Mutex halten | Medium |

### Zusätzliche Erkenntnisse

1. **RoutineTUNEventReader**: `NewDevice()` startet `RoutineTUNEventReader()` das auf TUN Events wartet und bei `tun.EventUp` ebenfalls `device.Up()` aufruft - potentielle Race Condition
2. **ICEBind auf Windows**: `ipv4.PacketConn` ist nil auf Windows, daher wird `createIPv4ReceiverFn` nie aufgerufen
3. **Named Pipe UAPI**: Windows nutzt `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\{name}` für IPC

---

## Bisherige Schritte

### 1. Code-Analyse durchgeführt
- `device_windows.go` - TunDevice mit Debug-Logging
- `usp.go` - USPConfigurer mit UAPI Listener
- `uapi_windows.go` - Named Pipe Implementation
- `ice_bind.go` - ICEBind Wrapper
- wireguard-go `device/device.go` - Core Device Lifecycle

### 2. Debug-Logging bereits in NetBird Fork
```go
// device_windows.go:109-148
func (t *TunDevice) Up() (*udpmux.UniversalUDPMuxDefault, error) {
    log.Infof(">>> TunDevice.Up() starting for %s", t.name)
    log.Info(">>> Calling device.Up()...")

    done := make(chan error, 1)
    go func() {
        done <- t.device.Up()
    }()

    ticker := time.NewTicker(5 * time.Second)
    // Log "Still waiting..." alle 5 Sekunden
}
```

### 3. wireguard-go Fork geklont
```bash
/work/vpn/netbird-fork/vendor-patches/wireguard-go/
```

### 4. Debug-Logging hinzugefügt (in Progress)
- `upLocked()` - vor/nach BindUpdate(), vor/nach ipcMutex.Lock()
- `BindUpdate()` - vor/nach closeBindLocked(), bind.Open(), etc.

---

## Nächste Schritte

1. **Debug-Logging vervollständigen**
   - `closeBindLocked()` annotieren
   - `startRouteListener()` annotieren

2. **go.mod Replace Directive**
   - Lokalen wireguard-go Fork verwenden
   - Rebuild mit Debug-Logging

3. **Windows VM Test**
   - Neue Binary deployen
   - Service starten
   - Logs analysieren

4. **Hypothese validieren**
   - Welcher der 3 Blocker ist der Schuldige?
   - Falls `netc.stopping.Wait()`: Warum gibt es vorherige Receiver?
   - Falls `ipcMutex.Lock()`: Wer hält den Mutex?

---

## Reproduktion

### Windows VM (10.0.0.160)
```powershell
# Reset
.\reset-netbird-machine.ps1 -Force

# Deploy neue Binary
# (von Linux: scp bin/netbird-machine.exe admin@10.0.0.160:C:/temp/)

# Install und Start
.\netbird-machine.exe install
Start-Service NetBirdMachine

# Beobachten
Get-EventLog -LogName Application -Source NetBirdMachine -Newest 20
```

### Erwartetes Verhalten (Bug)
```
[INFO] >>> TunDevice.Up() starting for wg-nb-machine
[INFO] >>> Calling device.Up()...
[WARN] >>> Still waiting for device.Up()...
[WARN] >>> Still waiting for device.Up()...
[WARN] >>> Still waiting for device.Up()...
# (blockiert indefinit)
```

### Erwartetes Verhalten (nach Fix)
```
[INFO] >>> TunDevice.Up() starting for wg-nb-machine
[INFO] >>> Calling device.Up()...
[INFO] >>> device.Up() completed successfully
[INFO] >>> GetICEMux() completed successfully
[INFO] >>> device is ready to use: wg-nb-machine
```

---

## Referenzen

- **Issue #113:** E2E Test auf Windows VM
- **Issue #109:** Signal/Relay Integration Gap (Parent)
- **PR #115:** PeerEngine Implementation
- **Plan:** `/home/jan/.claude/plans/sunny-juggling-starlight.md` (v4.5)

---

## Hypothese (Aktuell)

**Wahrscheinlichste Ursache:** `netc.stopping.Wait()` in `closeBindLocked()` wartet auf Receiver-Goroutinen die nie beendet werden.

**Begründung:**
- `BindUpdate()` ruft zuerst `closeBindLocked()` auf
- Wenn es vorherige Receiver gibt (von einem vorherigen Up-Versuch oder TUN Event), wartet `stopping.Wait()` darauf
- Die Receiver könnten blockiert sein wenn die Sockets nicht richtig geschlossen wurden

**Nächste Validierung:** Debug-Logging in `closeBindLocked()` hinzufügen um zu sehen ob `stopping.Wait()` blockiert.
