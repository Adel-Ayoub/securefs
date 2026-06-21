{{- define "securefs.name" -}}
{{- default .Chart.Name .Values.nameOverride -}}
{{- end -}}

{{- define "securefs.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "securefs.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "securefs.labels" -}}
app.kubernetes.io/name: {{ include "securefs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "securefs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "securefs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "securefs.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "securefs.fullname" . -}}
{{- end -}}
{{- end -}}

{{/* DB the server connects to: the in-cluster PgBouncer when enabled, else database.host */}}
{{- define "securefs.dbHost" -}}
{{- if .Values.pgbouncer.enabled -}}
{{- printf "%s-pgbouncer" (include "securefs.fullname" .) -}}
{{- else -}}
{{- .Values.database.host -}}
{{- end -}}
{{- end -}}

{{- define "securefs.dbPort" -}}
{{- if .Values.pgbouncer.enabled -}}
{{- .Values.pgbouncer.port -}}
{{- else -}}
{{- .Values.database.port -}}
{{- end -}}
{{- end -}}

{{- define "securefs.pgbouncerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "securefs.name" . }}-pgbouncer
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
