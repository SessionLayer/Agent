{{- define "sessionlayer-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sessionlayer-agent.fullname" -}}
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

{{- define "sessionlayer-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sessionlayer-agent.labels" -}}
helm.sh/chart: {{ include "sessionlayer-agent.chart" . }}
{{ include "sessionlayer-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: agent
app.kubernetes.io/part-of: sessionlayer
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
app.kubernetes.io/name carries the unprefixed chart name because the Control
Plane NetworkPolicy selects Agent pods by exactly this label.
*/}}
{{- define "sessionlayer-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sessionlayer-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "sessionlayer-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sessionlayer-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* A digest pins the exact bytes; a tag does not. Digest wins when set. */}}
{{- define "sessionlayer-agent.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end }}

{{- define "sessionlayer-agent.cpEndpoint" -}}
{{- default (printf "https://controlplane.%s.svc:9443" .Release.Namespace) .Values.controlPlane.endpoint -}}
{{- end }}

{{- define "sessionlayer-agent.cpServerName" -}}
{{- default (printf "controlplane.%s.svc" .Release.Namespace) .Values.controlPlane.serverName -}}
{{- end }}

{{/* Where the join credential is projected, whichever method supplies it. */}}
{{- define "sessionlayer-agent.joinMountPath" -}}/var/run/secrets/sessionlayer{{- end }}

{{/*
The run arguments. The Gateway endpoint flags are index-aligned by the binary,
so a failure domain given for one endpoint must be given for all of them.
*/}}
{{- define "sessionlayer-agent.args" -}}
{{- if not .Values.gateways -}}
{{- fail "sessionlayer-agent: set gateways to at least one entry. An Agent with no Gateway endpoint joins the Control Plane, holds an identity and serves no session, which looks healthy and reaches nothing." -}}
{{- end -}}
{{- $withDomain := 0 -}}
{{- range .Values.gateways -}}{{- if .failureDomain -}}{{- $withDomain = add1 $withDomain -}}{{- end -}}{{- end -}}
{{- if and (gt $withDomain 0) (ne $withDomain (len .Values.gateways)) -}}
{{- fail "sessionlayer-agent: give failureDomain for every gateway entry or for none. The binary aligns the flags by position and refuses a partial list." -}}
{{- end -}}
{{- if gt (int .Values.minControlChannels) (len .Values.gateways) -}}
{{- fail (printf "sessionlayer-agent: minControlChannels (%v) exceeds the %d gateway entries, so the Agent can never reach its own floor and never becomes healthy." .Values.minControlChannels (len .Values.gateways)) -}}
{{- end -}}
- run
- --node-name=$(NODE_NAME)
- --join-method={{ .Values.join.method }}
{{- if eq .Values.join.method "mtls" }}
- --operator-cert-file={{ include "sessionlayer-agent.joinMountPath" . }}/{{ .Values.join.certKey }}
- --operator-key-file={{ include "sessionlayer-agent.joinMountPath" . }}/{{ .Values.join.keyKey }}
{{- else }}
- --join-token-file={{ include "sessionlayer-agent.joinMountPath" . }}/token
{{- end }}
- --cp-endpoint={{ include "sessionlayer-agent.cpEndpoint" . }}
- --cp-server-name={{ include "sessionlayer-agent.cpServerName" . }}
- --bootstrap-ca-file=/etc/sessionlayer/{{ .Values.trustAnchor.key }}
- --data-dir={{ .Values.dataDir }}
{{- range .Values.gateways }}
- --gateway-endpoint={{ .endpoint }}
{{- end }}
{{- range .Values.gateways }}
- --gateway-server-name={{ required "sessionlayer-agent: give each gateway entry a serverName, the name that Gateway enrolled under and that its certificate carries. The binary's fallback is a development name, so an unset value fails the TLS handshake with nothing that names the cause." .serverName }}
{{- end }}
{{- if gt $withDomain 0 }}
{{- range .Values.gateways }}
- --gateway-failure-domain={{ .failureDomain }}
{{- end }}
{{- end }}
- --min-control-channels={{ .Values.minControlChannels }}
- --splice-addr={{ .Values.spliceAddr }}
- --max-concurrent-splices={{ .Values.maxConcurrentSplices }}
- --drain-deadline-secs={{ .Values.drainDeadlineSecs }}
{{- if .Values.requireFullLandlock }}
- --require-full-landlock
{{- end }}
{{- range .Values.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end }}
