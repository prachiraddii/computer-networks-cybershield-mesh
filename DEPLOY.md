# Share CyberShield Mesh with teammates

## Recommended: Streamlit Community Cloud

This project is prepared for Streamlit Community Cloud: the entry point is `app.py`, dependencies are in `requirements.txt`, and the UI theme is in `.streamlit/config.toml`.

1. Create a GitHub repository. Choose **public** if anyone with the link should view the app, or **private** if you want to invite only teammates.
2. Add the project files to the repository. Do not upload `.venv/`, `data/*.db`, `.env`, PCAPs, or files containing secrets.
3. Sign in at [share.streamlit.io](https://share.streamlit.io/) with GitHub and create an app.
4. Select the repository, its branch, and `app.py` as the app file. Keep `CYBERSHIELD_ENFORCEMENT` unset or set it to `simulation`.
5. Deploy, then copy the app's `*.streamlit.app` link to your teammates. For private sharing, use the app's sharing settings to invite the teammates by email. Community Cloud requires repository permissions to deploy; app viewers do not need write access to the source repository.

Official instructions: [deploy an app](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy) and [share an app](https://docs.streamlit.io/deploy/streamlit-community-cloud/share-your-app).

## Important sharing limits

- This is an unauthenticated teaching dashboard. Anyone who can open a public deployment can use its controls and see the same app instance's event database. Don't upload real or sensitive PCAPs, internal IP inventories, or credentials.
- The default provider is simulated quarantine. It changes CyberShield's displayed state only. Do not enable enforcement for a hosted classroom demo.
- The default SQLite database is local to the app container. On a hosted service, local files may not persist across restarts or redeployments. Treat cloud data as temporary demo data, not a shared durable incident database.
- A cloud app cannot sniff your teammates' or campus network. Use demo records or upload an authorized offline file. Live capture and Linux nftables enforcement require a suitably placed local sensor/lab and are not supplied by Community Cloud.
- If teammates need separate workspaces, each needs a separate deployment/database. This app does not provide accounts or per-user access controls.

## Run for a classroom demo on one laptop

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Connect the presentation laptop and teammates to the same trusted Wi-Fi, then launch with:

```bash
streamlit run app.py --server.address 0.0.0.0
```

Share the local network URL printed by Streamlit, such as `http://192.168.x.x:8501`. This exposes the unauthenticated dashboard to that network; use a trusted classroom network and synthetic data only. Stop the app after the demo with `Ctrl+C`.
