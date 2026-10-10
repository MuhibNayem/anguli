{{/*
Value validation lives in templates/validate.yaml, not here.

This file originally carried the guards as a bare top-level block. Helm parses
it but never executes a partials file outside its named templates, so the guard
was dead code: `helm template` succeeded with no Secret configured. A security
check that never executes is worse than none, because it reads as protection.
*/}}

{{- if lt (int .Values.overload.maxConcurrentRequests) 1 }}
{{- fail "overload.maxConcurrentRequests must be at least 1" }}
{{- end }}

{{- if .Values.autoscaling.enabled }}
{{- if lt (int .Values.autoscaling.minReplicas) 2 }}
{{- fail "autoscaling.minReplicas must be at least 2; a single-replica biometric service is a single point of failure" }}
{{- end }}
{{- end }}{{- define "anguli.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "anguli.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "anguli.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "anguli.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "anguli.selectorLabels" -}}
app.kubernetes.io/name: {{ include "anguli.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "anguli.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "anguli.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "anguli.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.repository $tag -}}
{{- end -}}