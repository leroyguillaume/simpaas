{{- define "simpaas-postgresql.backup.name" -}}
{{ default (printf "%s-backup" (include "simpaas-postgresql.name" .)) .Values.backup.name }}
{{- end -}}

{{- define "simpaas-postgresql.backup.pvc.name" -}}
{{- default (include "simpaas-postgresql.backup.name" .) .Values.backup.persistence.name }}
{{- end -}}

{{- define "simpaas-postgresql.labels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "simpaas-postgresql.name" -}}
{{- default .Release.Name .Values.name }}
{{- end -}}

{{- define "simpaas-postgresql.pgpool.podLabels" -}}
{{- $labels := merge .Values.pgpool.podLabels .Values.common.podLabels -}}
app.kubernetes.io/component: pgpool
app.kubernetes.io/instance: {{ include "simpaas-postgresql.name" . }}
app.kubernetes.io/name: {{ include "simpaas-postgresql.pgpool.name" . }}
{{- with $labels }}
{{- toYaml $labels }}
{{- end }}
{{- end -}}

{{- define "simpaas-postgresql.pgpool.name" -}}
{{- default (printf "%s-pgpool" (include "simpaas-postgresql.name" .)) .Values.pgpool.name }}
{{- end -}}

{{- define "simpaas-postgresql.postgresql.hooksConfigMap.name" -}}
{{- default (printf "%s-hooks" (include "simpaas-postgresql.postgresql.name" .)) .Values.postgresql.hooksConfigMap.name }}
{{- end -}}

{{- define "simpaas-postgresql.postgresql.domain" -}}
{{ printf "%s.%s.svc.%s" (include "simpaas-postgresql.postgresql.service.headlessName" .) .Release.Namespace .Values.common.clusterDomain }}
{{- end -}}

{{- define "simpaas-postgresql.postgresql.hosts" -}}
{{ range $i := until (int .Values.postgresql.replicas) }}{{ $i }}:{{ include "simpaas-postgresql.postgresql.subdomain" (dict "Release" $.Release "Values" $.Values "index" $i) }}:{{ $.Values.postgresql.service.port }},{{ end }}
{{- end -}}

{{- define "simpaas-postgresql.postgresql.name" -}}
{{- default (printf "%s-postgresql" (include "simpaas-postgresql.name" .)) .Values.postgresql.name }}
{{- end -}}

{{- define "simpaas-postgresql.postgresql.podLabels" -}}
{{- $labels := merge .Values.postgresql.podLabels .Values.common.podLabels -}}
app.kubernetes.io/component: postgresql
app.kubernetes.io/instance: {{ include "simpaas-postgresql.name" . }}
app.kubernetes.io/name: {{ include "simpaas-postgresql.postgresql.name" . }}
{{- with $labels }}
{{- toYaml $labels }}
{{- end }}
{{- end -}}

{{- define "simpaas-postgresql.postgresql.service.headlessName" -}}
{{- printf "%s-headless" (include "simpaas-postgresql.postgresql.name" .) }}
{{- end -}}

{{- define "simpaas-postgresql.postgresql.subdomain" -}}
{{ printf "%s-%d.%s" (include "simpaas-postgresql.postgresql.name" .) .index (include "simpaas-postgresql.postgresql.domain" .) }}
{{- end -}}

{{- define "simpaas-postgresql.serviceAccount.name" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "simpaas-postgresql.name" .) .Values.serviceAccount.name }}
{{- else }}
default
{{- end }}
{{- end -}}

{{- define "simpaas-postgresql.secret.name" -}}
{{- default (printf "%s-creds" (include "simpaas-postgresql.name" .)) .Values.secret.name }}
{{- end -}}

{{- define "utils.generateSecretIfDoesNotExist" -}}
{{- if .secret }}
{{- $secret := index .secret.data .key }}
{{- if empty $secret }}
{{- randAlphaNum 12 | b64enc }}
{{- else }}
{{- $secret }}
{{- end }}
{{- else }}
{{- randAlphaNum 12 | b64enc }}
{{- end }}
{{- end -}}

{{- define "utils.image" -}}
{{- $registry := default .common.registry .image.registry -}}
{{- $tag := default .common.tag .image.tag -}}
{{- if $registry }}
{{- printf "%s/%s:%s" $registry .image.repository $tag }}
{{- else }}
{{- printf "%s:%s" .image.repository $tag }}
{{- end -}}
{{- end -}}
