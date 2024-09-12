{{- define "simpaas-application.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "simpaas-application.componentName" -}}
{{ (printf "%s-%s" (include "simpaas-application.name" .) .component.name) | trunc 63 }}
{{- end }}

{{- define "simpaas-application.image" -}}
{{- $registry := default .global.registry .image.registry }}
{{- $repository := .image.repository }}
{{- if $registry }}
{{- $repository = printf "%s/%s" $registry .image.repository }}
{{- end }}
{{- printf "%s:%s" $repository .image.tag }}
{{- end }}

{{- define "simpaas-application.labels" -}}
helm.sh/chart: {{ include "simpaas-application.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
simpaas.gleroy.dev/application: {{ include "simpaas-application.name" . }}
{{- with .Values.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "simpaas-application.name" -}}
{{ default .Release.Name .Values.nameOverride | trunc 63 }}
{{- end }}

{{- define "simpaas-application.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "simpaas-application.name" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "simpaas-application.component.labels" -}}
app.kubernetes.io/name: {{ include "simpaas-application.componentName" . }}
app.kubernetes.io/instance: {{ include "simpaas-application.name" . }}
app.kubernetes.io/component: {{ .component.name }}
simpaas.gleroy.dev/application: {{ include "simpaas-application.name" . }}
simpaas.gleroy.dev/application-component: {{ .component.name }}
{{- end }}
