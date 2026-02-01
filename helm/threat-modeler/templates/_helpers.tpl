{{/*
Expand the name of the chart.
*/}}
{{- define "threat-modeler.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "threat-modeler.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "threat-modeler.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "threat-modeler.labels" -}}
helm.sh/chart: {{ include "threat-modeler.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Backend labels
*/}}
{{- define "threat-modeler.backend.labels" -}}
{{ include "threat-modeler.labels" . }}
app.kubernetes.io/name: backend
app.kubernetes.io/component: api
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "threat-modeler.frontend.labels" -}}
{{ include "threat-modeler.labels" . }}
app.kubernetes.io/name: frontend
app.kubernetes.io/component: ui
{{- end }}

{{/*
Backend selector labels
*/}}
{{- define "threat-modeler.backend.selectorLabels" -}}
app: backend
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "threat-modeler.frontend.selectorLabels" -}}
app: frontend
{{- end }}
