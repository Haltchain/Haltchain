{{/*
Expand the name of the chart.
*/}}
{{- define "haltchain-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "haltchain-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "haltchain-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "haltchain-operator.labels" -}}
helm.sh/chart: {{ include "haltchain-operator.chart" . }}
{{ include "haltchain-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "haltchain-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "haltchain-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: {{ include "haltchain-operator.fullname" . }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "haltchain-operator.serviceAccountName" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- include "haltchain-operator.fullname" . }}
{{- end }}
{{- end }}

{{/*
Webhook service name
*/}}
{{- define "haltchain-operator.webhookServiceName" -}}
{{ include "haltchain-operator.fullname" . }}-webhook
{{- end }}
