{{- define "simpaas.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "simpaas.env" -}}
{{- $logFilter := default .Values.common.logFilter .Service.logFilter -}}
{{- if $logFilter }}
- name: LOG_FILTER
  value: {{ $logFilter }}
{{- end }}
{{- if .Values.common.otel.enabled }}
- name: OTEL_COLLECTOR_URL
  value: {{ default (printf "http://%s-opentelemetry-collector:4317" .Release.Name) .Values.common.otel.collectorUrl }}
{{- end }}
{{- end -}}

{{- define "simpaas.fqdn" -}}
{{- if .Ingress.domain -}}
{{ default (printf "%s.%s" .Ingress.domain .Values.ingress.domain) .Ingress.fqdn }}
{{- else -}}
{{ default .Values.ingress.domain .Ingress.fqdn }}
{{- end -}}
{{- end -}}

{{- define "simpaas.labels" -}}
helm.sh/chart: {{ include "simpaas.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "simpaas.serviceAccountName" -}}
{{ default .Release.Name .Values.serviceAccount.name }}
{{- end -}}

{{- define "simpaas.api.labels" -}}
{{ include "simpaas.labels" . }}
app.kubernetes.io/version: {{ include "simpaas.api.tag" . }}
{{ include "simpaas.api.selectorLabels" . }}
{{- end }}

{{- define "simpaas.api.name" -}}
{{ printf "%s-api" .Release.Name | trunc 63 | trimSuffix "-"  }}
{{- end -}}

{{- define "simpaas.api.jwtSecretName" -}}
{{ default (printf "%s-jwt" .Release.Name) .Values.api.jwtSecret.name  }}
{{- end -}}

{{- define "simpaas.api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "simpaas.api.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: api
{{- end }}

{{- define "simpaas.api.tag" -}}
{{ default .Chart.AppVersion (default .Values.common.image.tag .Values.api.image.tag) }}
{{- end -}}

{{- define "simpaas.op.labels" -}}
{{ include "simpaas.labels" . }}
app.kubernetes.io/version: {{ include "simpaas.op.tag" . }}
{{ include "simpaas.op.selectorLabels" . }}
{{- end }}

{{- define "simpaas.op.name" -}}
{{ printf "%s-op" .Release.Name| trunc 63 | trimSuffix "-"  }}
{{- end -}}

{{- define "simpaas.op.selectorLabels" -}}
app.kubernetes.io/name: {{ include "simpaas.op.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: op
{{- end }}

{{- define "simpaas.op.tag" -}}
{{ default .Chart.AppVersion (default .Values.common.image.tag .Values.op.image.tag) }}
{{- end -}}

{{- define "simpaas.webapp.labels" -}}
{{ include "simpaas.labels" . }}
app.kubernetes.io/version: {{ include "simpaas.webapp.tag" . }}
{{ include "simpaas.webapp.selectorLabels" . }}
{{- end }}

{{- define "simpaas.webapp.name" -}}
{{ printf "%s-webapp" .Release.Name| trunc 63 | trimSuffix "-"  }}
{{- end -}}

{{- define "simpaas.webapp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "simpaas.webapp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: webapp
{{- end }}

{{- define "simpaas.webapp.tag" -}}
{{ default .Chart.AppVersion (default .Values.common.image.tag .Values.webapp.image.tag) }}
{{- end -}}

{{- define "simpaas.smtp.labels" -}}
{{ include "simpaas.labels" . }}
app.kubernetes.io/version: {{ .Values.smtp.image.tag }}
{{ include "simpaas.smtp.selectorLabels" . }}
{{- end }}

{{- define "simpaas.smtp.name" -}}
{{ printf "%s-smtp" .Release.Name| trunc 63 | trimSuffix "-"  }}
{{- end -}}

{{- define "simpaas.smtp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "simpaas.smtp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: smtp
{{- end }}
