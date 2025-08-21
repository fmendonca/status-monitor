Exemplo values.yaml

env:
  MONITOR_FQDNS: "cdn01.quay.io,cdn02.quay.io,cdn03.quay.io"
  IPV6_ENABLED: "0"
  MONITOR_INTERVAL: "300"
route:
  enabled: true
  host: status-monitor.apps.seucluster.example
persistence:
  enabled: true
  size: 2Gi
resources:
  requests:
    cpu: 50m
    memory: 128Mi
  limits:
    cpu: 300m
    memory: 384Mi

Exemplo para instalar o pacote: helm install status-monitor ./status-monitor -n status-monitor -f my-values.yaml
