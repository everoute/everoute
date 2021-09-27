{{ define "packages" }}
  <html lang="en">
    <head>
      <meta charset="utf-8">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
      <style type="text/css">
        td p {
          margin-bottom: 0
        }
        code {
          color: #b70000;
          display: inline-block;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h2 style="border-bottom: 3px solid lightslategray; line-height: 80px">API Groups</h2>
        <p>The API Groups and their versions are summarized in the following list.</p>
        {{- range .packages -}}
          <li><a href="#{{- packageAnchorID . -}}">{{- packageDisplayName . -}}</a></li>
        {{- end -}}

        {{- range .packages -}}
          <h2 style="border-bottom: 3px solid lightslategray; line-height: 80px" id="{{- packageAnchorID . -}}">{{- packageDisplayName . -}}</h2>
          <h3>Resource Types:</h3>
          <ul>
          {{- range (visibleTypes (sortedTypes .Types)) -}}
              {{ if isExportedType . -}}
                  <li>
                      <a href="{{ linkForType . }}">{{ typeDisplayName . }}</a>
                  </li>
              {{- end }}
          {{- end -}}
          </ul>

          {{ range (visibleTypes (sortedTypes .Types))}}
              {{ template "type" .  }}
          {{ end }}
        {{ end }}

      </div>
    </body>
  </html>
{{ end }}
