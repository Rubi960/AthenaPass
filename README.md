<!--
SPDX-FileCopyrightText: 2026 Rubi960 & Ryosh1

SPDX-License-Identifier: MIT
-->

# :shield: AthenaPass

## Table of Contents

- [Table of Contents](#table-of-contents)
- [:scroll: Description](#scroll-description)
- [:black\_nib: Authors](#black_nib-authors)
- [:beginner: Features](#beginner-features)
- [:file\_folder: Repository Structure](#file_folder-repository-structure)
- [:electric\_plug: Installation](#electric_plug-installation)
- [:wrench: Usage](#wrench-usage)
- [:clipboard: Development \& Contribution](#clipboard-development--contribution)
  - [Running locally](#running-locally)
- [:gear: Deployment](#gear-deployment)
- [:balance\_scale: License](#balance_scale-license)

## :scroll: Description

AthenaPass allows users to store and manage their passwords securely. It employs
modern cryptographic practices such as Secure Remote Password (SRP) for
authentication and AES‑GCM for encryption of stored data. The project is
implemented with a Python/Flask backend and a TypeScript web extension/Linux &
Windows desktop frontend.

## :black_nib: Authors

Made by:

- **Rubén Diz Martínez**
- **Pablo Juncal Moreira**

You can also check the list of all [contributors](https://github.com/your/project/contributors) who have participated in this project.

## :beginner: Features

- **Secure Remote Password (SRP)** zero‑knowledge authentication.
- **SQLite persistence** for user and password data (suitable for Docker
  volumes).
- **Browser extension UI** implemented in TypeScript using Web Crypto APIs.
- **AES‑GCM encryption** of individual password entries and local email storage.
- **Password generator & security checks** built into the client.
- Clean modular design, easy to extend and dockerize.

## :file_folder: Repository Structure

The source tree is organised into a few top‑level folders and files:

```
AthenaPass/                 # project root
├─ docker/                  # Python backend and Docker support
│  ├─ server.py             # Flask application implementing the API
│  ├─ client.py             # simple CLI client used for testing
│  ├─ requirements.txt      # Python dependencies
│  ├─ Dockerfile            # container image definition
│  └─ setup.sh              # convenience script to build & run container
├─ extension/               # browser extension source (TypeScript)
│  ├─ popup.ts              # main UI logic
│  ├─ popup.html            # extension popup markup
│  ├─ style.css             # styles shared by extension and desktop
│  ├─ package.json          # JS build scripts & dependencies
│  └─ tsconfig.json         # TypeScript configuration
├─ desktop/                 # Electron desktop wrapper (uses extension code)
│  ├─ main.js               # entry point for desktop app
│  ├─ renderer.js/ts        # UI glue code
│  ├─ package.json          # build/install scripts for desktop
│  └─ index.html            # UI shell for desktop app
├─ mock_server/             # lightweight server used during early development
│  └─ server.py
├─ scripts/                 # build and sync helpers
│  └─ sync-desktop.js       # copies extension output into desktop package
├─ CONTRIBUTING.md          # contribution guidelines
├─ README.md                # this file
└─ .gitignore               # files excluded from version control
```

Each component is fairly self‑contained; the extension and desktop folders
share most of their code, while the `docker` directory houses the backend
service and associated deployment artifacts.

## :electric_plug: Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/Rubi960/AthenaPass.git
   cd AthenaPass
   ```

2. **Install dependencies**
   To intall the frontend extension and other components use npm install:

   ```bash
   npm install --prefix extension
   npm install --prefix desktop
   ```

3. **Build the extension and the desktop**:
    Copies files from extension to desktop changing the variables to adapt it

   ```bash
   npm run sync
   ```

    Install all dependencies

   ```bash
   npm run install:all
   ```

    Build the web extension and linux and windows desktop apps and launch a test
    browser with the extension installed

   ```bash
   npm run build:all
   ```

4. **Prepare the server**

   The Python backend runs in its own virtual environment or via Docker. To use
   Docker (recommended):

   ```bash
   chmod +x docker/setup.sh
   cd docker
   ./setup.sh
   ```

   Alternatively, create a Python venv, install requirements and run `server.py`:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r docker/requirements.txt
   python docker/server.py
   ```

## :wrench: Usage

- Load the extension in your browser (chrome://extensions → "Load unpacked" →
  select `extension/` folder after building) or use `npm run build:all` to
  automatically launch a web browser with the extension installed.
- Open the popup and create your account or log in. The extension communicates
  with the backend at `http://localhost:4134` by default.
- Add, edit, delete passwords; they are stored encrypted on the server and
  displayed only after unlocking with your master password.
- Use the generator tab to produce strong passwords.

## :clipboard: Development & Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute.
The project follows standard open‑source practices: forks, PRs, issues, and
code reviews.

### Running locally

- Backend: run `python docker/server.py` or via Docker as shown above.
- Frontend: changes to `extension/popup.ts` require running the TypeScript
  build/packager defined in `extension/package.json`.

## :gear: Deployment

A simple deployment can be achieved by executing the following commands:

```bash
chmod +x docker/setup.sh
docker/setup.sh
npm run build:all
```

## :balance_scale: License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
