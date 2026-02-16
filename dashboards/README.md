### 📊 Dashboard Integration
This repository includes a pre-configured dashboard for OpenSearch/Wazuh. 
To import it into your own instance:
1. Go to **Stack Management** > **Saved Objects**.
2. Click on **Import** and select the file `dashboards/proteusos-dashboard.ndjson` from this repository.
3. The dashboard will automatically link to your `wazuh-alerts-*` and `wazuh-monitoring-*` indices.

*Features included:* Real-time alert levels, agent health status, file integrity monitoring tracking, and critical threat distribution.
