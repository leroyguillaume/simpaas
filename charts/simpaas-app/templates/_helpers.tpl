{{- define "simpaas-app.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "simpaas-app.labels" -}}
helm.sh/chart: {{ include "simpaas-app.chart" . }}
app.kubernetes.io/managed-by: simpaas
simpaas.gleroy.dev/app: {{ .Release.Name }}
{{- end }}

{{- define "simpaas-app.service.labels" -}}
{{ include "simpaas-app.labels" . }}
app.kubernetes.io/version: {{ .Service.tag | quote }}
{{ include "simpaas-app.service.selectorLabels" . }}
{{- end }}

{{- define "simpaas-app.service.name" -}}
{{ printf "%s-%s" .Release.Name .Service.name | trunc 63 | trimSuffix "-"  }}
{{- end -}}

{{- define "simpaas-app.service.tlsSecretName" -}}
{{ printf "%s-tls" .Expose.ingress.domain }}
{{- end }}

{{- define "simpaas-app.service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "simpaas-app.service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .Service.name }}
simpaas.gleroy.dev/service: {{ .Service.name }}
{{- end }}

{{- define "simpaas-app.serviceAccountName" -}}
{{ default .Release.Name .Values.serviceAccount.name }}
{{- end -}}
