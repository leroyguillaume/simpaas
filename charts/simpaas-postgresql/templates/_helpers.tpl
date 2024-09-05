{{- define "simpaas-postgresql.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "simpaas-postgresql.image" -}}
{{- $registry := default .global.registry .image.registry }}
{{- $repository := .image.repository }}
{{- if $registry }}
{{- $repository = printf "%s/%s" $registry .image.repository }}
{{- end }}
{{- printf "%s:%s" $repository .image.tag }}
{{- end }}

{{- define "simpaas-postgresql.labels" -}}
helm.sh/chart: {{ include "simpaas-postgresql.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "simpaas-postgresql.name" -}}
{{ default .Release.Name .Values.nameOverride | trunc 43 }}
{{- end }}

{{- define "simpaas-postgresql.probe" -}}
initialDelaySeconds: {{ .initialDelaySeconds }}
periodSeconds: {{ .periodSeconds }}
timeoutSeconds: {{ .timeoutSeconds }}
successThreshold: {{ .successThreshold }}
failureThreshold: {{ .failureThreshold }}
{{- end }}

{{- define "simpaas-postgresql.secretName" -}}
{{- default (printf "%s-creds" (include "simpaas-postgresql.name" .)) .Values.secret.name }}
{{- end }}

{{- define "simpaas-postgresql.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "simpaas-postgresql.name" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "simpaas-postgresql.pgpool.labels" -}}
app.kubernetes.io/name: {{ include "simpaas-postgresql.pgpool.name" . }}
app.kubernetes.io/instance: {{ include "simpaas-postgresql.name" . }}
app.kubernetes.io/component: pgpool
{{- end }}

{{- define "simpaas-postgresql.pgpool.name" -}}
{{- (default (printf "%s-pgpool" (include "simpaas-postgresql.name" .)) (.Values.pgpool.nameOverride | trunc 63)) }}
{{- end }}

{{- define "simpaas-postgresql.postgresql.headlessServiceName" -}}
{{ printf "%s-headless" (include "simpaas-postgresql.postgresql.name" .) }}
{{- end }}

{{- define "simpaas-postgresql.postgresql.labels" -}}
app.kubernetes.io/name: {{ include "simpaas-postgresql.postgresql.name" . }}
app.kubernetes.io/instance: {{ include "simpaas-postgresql.name" . }}
app.kubernetes.io/component: postgresql
{{- end }}

{{- define "simpaas-postgresql.postgresql.name" -}}
{{- (default (printf "%s-postgresql" (include "simpaas-postgresql.name" .)) (.Values.postgresql.nameOverride | trunc 54)) }}
{{- end }}
