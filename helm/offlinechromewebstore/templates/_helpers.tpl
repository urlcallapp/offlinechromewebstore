{{- define "ocws.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ocws.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "ocws.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ocws.labels" -}}
app.kubernetes.io/name: {{ include "ocws.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "ocws.image" -}}
{{- printf "%s/%s:%s" .registry .repository .tag -}}
{{- end -}}
