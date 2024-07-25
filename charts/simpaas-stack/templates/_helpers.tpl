{{- define "simpaas-stack.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "simpaas-stack.labels" -}}
helm.sh/chart: {{ include "simpaas-stack.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "simpaas-stack.smtp.labels" -}}
{{ include "simpaas-stack.labels" . }}
app.kubernetes.io/version: {{ .Values.smtp.image.tag | quote }}
{{ include "simpaas-stack.smtp.selectorLabels" . }}
{{- end }}

{{- define "simpaas-stack.smtp.name" -}}
{{ printf "%s-smtp" .Release.Name| trunc 63 | trimSuffix "-"  }}
{{- end -}}

{{- define "simpaas-stack.smtp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "simpaas-stack.smtp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: smtp
{{- end }}

{{- define "simpaas-stack.swaggerUi.labels" -}}
{{ include "simpaas-stack.labels" . }}
app.kubernetes.io/version: {{ .Values.swaggerUi.image.tag | quote }}
{{ include "simpaas-stack.swaggerUi.selectorLabels" . }}
{{- end }}

{{- define "simpaas-stack.swaggerUi.name" -}}
{{ printf "%s-swagger-ui" .Release.Name | trunc 63 | trimSuffix "-"  }}
{{- end -}}

{{- define "simpaas-stack.swaggerUi.selectorLabels" -}}
app.kubernetes.io/name: {{ include "simpaas-stack.swaggerUi.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: swagger-ui
{{- end }}
