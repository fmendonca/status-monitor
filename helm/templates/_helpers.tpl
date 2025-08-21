{{- define "status-monitor.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "status-monitor.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "status-monitor.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "status-monitor.labels" -}}
app.kubernetes.io/name: {{ include "status-monitor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- if .Values.commonLabels }}
{{- toYaml .Values.commonLabels | nindent 0 }}
{{- end }}
{{- end -}}

{{- define "status-monitor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "status-monitor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
