# Union

Software KVM (keyboard/video/mouse) cross-platform — compartilha mouse, teclado e clipboard entre Ubuntu/X11, macOS e Windows na mesma rede local. Escrito em Rust.

## Status

**v0.2 — produto utilizável.** 25 testes verdes (unit + TLS+PSK end-to-end + smoke localhost). Build release zero-warnings em Linux/macOS/Windows. Limitações restantes documentadas abaixo.

## Arquitetura

- **Server**: roda na máquina dona do teclado/mouse físico. Captura input e roteia ao client em foco.
- **Client**: roda em cada máquina remota. Recebe eventos e injeta no SO local.
- **Multi-monitor**: edge-crossing usa o bounding box do *virtual desktop* (todos os monitores), não apenas o primário.
- **Layout 2D configurável**: cada client tem `position = "left" | "right" | "above" | "below"` em `server.toml`. Edge-crossing usa as quatro bordas da tela do server; clients sem entrada caem em `right` por default.
- Clients detectam a borda de saída (espelhada à de entrada) e devolvem o foco automaticamente. Hotkey `Ctrl+Alt+→` / `Ctrl+Alt+←` continua disponível para cycle linear manual.
- **Indicador de foco**: notificação do SO em cada mudança de foco (configurável via `notify_on_focus`).
- **TLS 1.3** com pinning de fingerprint (TOFU). Autenticação por **PSK** (HMAC-SHA256 challenge/response), com rate-limit por IP após 3 falhas (backoff exponencial até 5min) e timeout de 10s no handshake.
- **Heartbeat**: Ping/Pong a cada 10s; sessões sem tráfego por 30s são derrubadas — o client reconnecta com backoff.
- **Modifiers safety**: ao perder foco ou cair a sessão, o client solta Shift/Ctrl/Alt/Meta no SO local (evita "tecla colada").
- **Rotação de cert detectável**: quando a fingerprint do server muda, o client grava `pending_fingerprint.txt` com instruções e sai com código 2 (não reconecta silenciosamente contra MITM).
- Clipboard de texto (default 1 MiB, truncado em UTF-8 + notificação) **e clipboard de imagens comprimido em PNG** na wire (teto de 8 MiB pós-compressão; acima disso descarta + notifica).
- Discovery opcional via mDNS (`_union._tcp.local.`): o server anuncia porta + fingerprint no TXT; clients com `discover = true` dispensam o passo manual de copiar o hash.

## Build

```bash
cargo build --release
```

Binários em `target/release/`:
- `union-server`
- `union-client`
- `union-gui` (control panel egui)

## Uso por CLI

### 1. Server (máquina com teclado/mouse)

```bash
./target/release/union-server --config examples/server.toml
```

Saída na primeira execução inclui a linha:
```
==> share this fingerprint with each client: <sha256 hex>
```

Copie esse hash; cada client precisa dele para pinning de cert.

### 2. Client

Edite `examples/client.toml` com endereço do server e o fingerprint (ou ative `discover = true` para descoberta via mDNS, dispensando os dois campos), depois:

```bash
./target/release/union-client --config examples/client.toml
```

### 3. Operação

Com server + 1 ou mais clients conectados:
- Move o cursor até a borda direita/esquerda da tela do server → foco passa para o próximo/anterior client.
- Já no client, move até a borda oposta de entrada → foco volta para o server (ou para o client anterior na cadeia).
- `Ctrl+Alt+→` / `Ctrl+Alt+←`: cycle manual (também volta para local depois do último).

Enquanto remoto, mouse/teclado são capturados no server (o cursor físico fica preso na borda de saída) e os eventos vão para o client de foco. Clipboard de texto e imagem sincroniza nos dois sentidos automaticamente.

## GUI (egui)

```bash
./target/release/union-gui
```

Painel de controle que:

- Carrega o `server.toml` / `client.toml` existente ao abrir (do diretório de config padrão, `UNION_CONFIG_DIR` se setada).
- Valida os campos obrigatórios antes de permitir Start (PSK, hostname, fingerprint hex 64 chars — fingerprint dispensado quando `discover` está ligado).
- Expõe Hotkey (combobox de teclas + checkboxes de modifiers) e Layout 2D (lista editável `hostname↔position`) sem precisar editar TOML.
- Botão **Test connection** no client tab que faz TCP+TLS+PSK contra o server e mostra OK/erro antes de iniciar o daemon.
- Spawna o binário do daemon vizinho (`union-server` / `union-client`), reaping em background e tail do stdout/stderr em um buffer rolante de 400 linhas.
- Painel **Runtime status** lê `~/.config/union/runtime/status.json` (1s polling) e mostra PID, fingerprint, focus atual, clients conectados (hostname/position/screen) e métricas (sessions/focus switches/auth failures/bytes de clipboard).
- Exibe o fingerprint SHA-256 do cert na aba Server lendo `<cert_dir>/server.crt` direto — sem precisar copiar do log.

## Auto-start

```bash
./target/release/union-server --config /etc/union/server.toml --install-autostart
./target/release/union-client --config /etc/union/client.toml --install-autostart
```

Registra como serviço **per-user** (sem root/admin):
- **Linux**: unidade systemd em `~/.config/systemd/user/dev.union.{server,client}.service`, com `daemon-reload` + `enable --now`.
- **macOS**: LaunchAgent em `~/Library/LaunchAgents/dev.union.{server,client}.plist`, com `launchctl bootstrap`.
- **Windows**: valor sob `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

Use `--uninstall-autostart` para remover.

## Indicador de foco

Duas opções, configuráveis por TOML/GUI:

- `notify_on_focus = true` (default): notificação do SO via `notify-rust` em cada mudança de foco.
- `overlay_on_focus = true` (opt-in): banner egui transparente e *mouse-passthrough* aparece no canto superior direito por ~800ms ("UNION → hostname"). Substitui ou complementa a notificação.

## Hot-reload de config

O server faz polling do mtime do TOML a cada 1s. Mudanças em `[layout.X]` e `notify_on_focus` aplicam **sem restart** — clientes já conectados têm o `position` atualizado in-place. Mudanças em `bind/port/psk/cert_dir/hotkey` são detectadas e logam um warning explícito (precisam de restart).

## Permissões por SO

### macOS
- **Accessibility**: necessário para capturar e injetar input. Conceda em *System Settings → Privacy & Security → Accessibility* tanto para `union-server` quanto `union-client`. Sem isso o binário roda em modo "relay-only" (só passa clipboard).
- Se quiser persistência da permissão após reinstalar, assine o app com Developer ID.

### Linux (X11)
- Funciona out-of-the-box em sessões X11.

### Windows
- Funciona, mas low-level hooks não conseguem injetar em janelas elevadas (UAC). Para suporte completo, rode o serviço como administrador.

## Crates do workspace

| Crate | Responsabilidade | Testes |
|---|---|---|
| `protocol` | Tipos de mensagem, framing length-prefix, bincode | 5 ✅ |
| `union-tls` | TLS rustls + cert auto-assinado + PSK | 7 ✅ |
| `union-session` | Handshake (Hello → Challenge → Response) | 3 ✅ |
| `input-inject` | Injeção de eventos via enigo (3 OSes) | 3 ✅ |
| `input-capture` | Captura global via rdev (CGEventTap/XInput2/SetWindowsHookEx) | — |
| `clipboard-sync` | Watcher + chunking + reassembly + truncamento UTF-8 | 2 ✅ |
| `union-server` | Daemon servidor | — |
| `union-client` | Daemon cliente | — |
| `union-gui` | Control panel egui | — |

20 testes passando.

## Smoke test localhost

Validado em sessão real:

```
[server] generated new TLS cert
[server] listening on 127.0.0.1:24800
[client] connecting to 127.0.0.1:24800
[client] authenticated                       ← TLS pinning + PSK ok
[client] local screen: 1440x900
[server] client connected peer=127.0.0.1:50268 client=smoke-test-client id=1
```

## Limitações conhecidas

1. **Captura no Windows não consome eventos elevados** — limitação dos low-level hooks do Win32; rode como administrador para suporte completo.
2. **rdev pode falhar a primeira invocação no macOS** se Accessibility não estiver concedida; o daemon cai em modo relay-only e segue só com clipboard.
3. **Layout 2D não suporta chains** — cada `position` admite um client. Múltiplos clients no mesmo eixo precisariam de coordenadas relativas (v0.4).
4. **Cursor absoluto multi-monitor** — `MoveAbs` do enigo usa coords do display primary; em setup multi-monitor do *client*, o cursor inicial pode aparecer no monitor errado. Edge-crossing entre/dentro de monitores do server funciona.
5. **Clipboard de imagens descarta payloads >8 MiB pós-PNG** com notificação.
6. **Drag-and-drop de arquivos** — não implementado; precisaria de hooks nativos por OS (Win32 OLE, NSDragging, XDND). Roadmap v0.4.
7. **GUI não foi validada visualmente nesta sessão** — compila e a estrutura está pronta (load/save, validação, log tail, fingerprint visível), mas pode precisar de tweaks em uso real.

## Packaging / Instaladores

Cada plataforma tem seu próprio fluxo nativo. CI em `.github/workflows/release.yml` dispara automaticamente em tags `v*` e publica os três artefatos como GitHub Release.

### Ubuntu / Debian — `.deb`

```bash
cargo install cargo-deb
sudo apt-get install -y libx11-dev libxi-dev libxtst-dev libgl1-mesa-dev
bash packaging/linux/build.sh
# → target/debian/union-server_<v>_amd64.deb
#   target/debian/union-client_<v>_amd64.deb
#   target/debian/union-gui_<v>_amd64.deb
```

Cada `.deb` instala o binário em `/usr/bin/`, o exemplo em `/etc/union/`, service unit em `/lib/systemd/user/`, ícone em `/usr/share/icons/hicolor/scalable/apps/union.svg` e atualiza os caches de desktop/icon via postinst. Na primeira invocação do serviço (`systemctl --user enable --now union-server`), um `ExecStartPre` seedea `~/.config/union/server.toml` a partir do exemplo se ainda não existir — sem passos manuais de cópia.

### macOS — `.dmg`

```bash
bash packaging/macos/build.sh
# → target/Union-<v>.dmg
```

Empacota `Union.app` com um wrapper `Contents/MacOS/union` que (1) cria `~/Library/Application Support/Union/` se não existir, (2) seeda `server.toml` e `client.toml` a partir dos exemplos em `Contents/Resources/`, (3) define `PATH` e `UNION_CONFIG_DIR` antes de exec o `union-gui` real. O bundle também inclui `union.icns` gerado via `iconutil` e templates `dev.union.server.plist` / `dev.union.client.plist` + helpers (`install-launchagent.sh server|client`) para auto-start opcional. Para builds assinadas/notarizadas:

```bash
CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
NOTARIZE_PROFILE="union-notary" \
bash packaging/macos/build.sh
```

Universal binary (arm64 + x86_64) é montado automaticamente pelo workflow do CI; localmente o script usa o triple do host.

### Windows — `.msi`

```powershell
cargo install cargo-wix
choco install wixtoolset
.\packaging\windows\build.ps1
# → target\wix\union-gui-<v>-x86_64.msi
```

Instala tudo em `C:\Program Files\Union\`, adiciona o diretório ao `PATH` do sistema, cria atalho no Start Menu, instala uma regra de Windows Firewall (TCP 24800, escopo local-subnet) para `union-server.exe` e seedea `%APPDATA%\Union\server.toml` + `client.toml` per-user a partir dos exemplos via componentes MSI advertising (executados na primeira vez que cada usuário entra). O binário do GUI é compilado com `windows_subsystem = "windows"` em release, então não abre console. Detalhes de assinatura em [`packaging/windows/README.md`](packaging/windows/README.md).

## Próximos passos (v0.3+)

- Drag-and-drop de arquivos (Win32 OLE / NSDragging / XDND)
- Layout 2D com chains (múltiplos clients no mesmo eixo + coordenadas relativas)
- Overlay de foco com janela egui transparente (substitui a notification)
- Tray icon + auto-start nativo (`launchd` / `systemctl --user` / Windows service)
- WebP no clipboard de imagem (PNG é lossless mas grande)
- Lock-screen sync entre máquinas
