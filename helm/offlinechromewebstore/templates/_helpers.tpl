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

{{- define "ocws.openshiftPod" -}}
{{- if .Values.openshift.enabled }}
automountServiceAccountToken: false
securityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
{{- end }}
{{- end -}}

{{- define "ocws.openshiftContainer" -}}
{{- if .Values.openshift.enabled }}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
{{- end }}
{{- end -}}
