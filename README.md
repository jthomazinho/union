# Union

Software KVM (keyboard/video/mouse) cross-platform — compartilha mouse, teclado e clipboard entre Ubuntu/X11, macOS e Windows na mesma rede local. Escrito em Rust.

## Status

**MVP funcional**, validado por testes unitários, testes de integração TLS+PSK end-to-end e smoke test localhost. Não use em produção ainda — falta polimento (auto-reconnect, instaladores, descoberta automática).

## Arquitetura

- **Server**: roda na máquina dona do teclado/mouse físico. Captura input e roteia ao client em foco.
- **Client**: roda em cada máquina remota. Recebe eventos e injeta no SO local.
- Topologia em linha: ciclar foco com `Ctrl+Alt+→` / `Ctrl+Alt+←` (configurável).
- TLS 1.3 com pinning de fingerprint (TOFU). Autenticação por PSK (HMAC-SHA256 challenge/response).
- Clipboard texto sincronizado com limite configurável (default 1 MiB); acima do limite trunca preservando borda UTF-8 e notifica.

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

Edite `examples/client.toml` com endereço do server e o fingerprint, depois:

```bash
./target/release/union-client --config examples/client.toml
```

### 3. Operação

Com server + 1 ou mais clients conectados:
- `Ctrl+Alt+→`: foco vai para o próximo client (ou volta para local após o último).
- `Ctrl+Alt+←`: foco vai para o client anterior.

Enquanto remoto, mouse/teclado são capturados localmente e enviados ao client de foco. Clipboard sincroniza nos dois sentidos automaticamente.

## GUI (egui)

```bash
./target/release/union-gui
```

Janela permite alternar entre modo Server/Client, preencher config e iniciar o daemon como subprocesso. **Não validada visualmente nesta sessão** — código compila e o esqueleto está pronto, mas a UX precisa de iteração.

## Permissões por SO

### macOS
- **Accessibility**: necessário para capturar e injetar input. Conceda em *System Settings → Privacy & Security → Accessibility* tanto para `union-server` quanto `union-client`. Sem isso o binário roda em modo "relay-only" (só passa clipboard).
- Se quiser persistência da permissão após reinstalar, assine o app com Developer ID.

### Linux (X11)
- Funciona out-of-the-box. **Wayland não suportado** — use sessão X11.

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

## Limitações conhecidas do MVP

1. **Edge crossing automático ausente** — usa hotkey ao invés de detectar cursor cruzando borda da tela. Tarefa para próxima fase (precisa do layout 2D).
2. **Captura no Windows não consome eventos elevados** — limitação dos low-level hooks fora de privilégio admin.
3. **rdev pode falhar a primeira invocação no macOS** se Accessibility não estiver concedida; o daemon cai em modo relay-only mas continua aceitando conexões para clipboard.
4. **Clipboard imagens não suportado** — texto apenas.
5. **Sem auto-reconnect** — se a conexão cair, o client encerra. Roteador a relançar (systemd/launchd) ou rodar com `while true; do ...; done`.
6. **GUI não validada visualmente** — egui app compila mas precisa de iteração de UX.

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

## Próximos passos (Phase 2+)

- Detecção de border crossing com layout 2D
- mDNS discovery (zeroconf)
- Drag-and-drop entre máquinas
- Clipboard de imagens
- Tray icon + auto-start
- libei nativo para suporte Wayland
