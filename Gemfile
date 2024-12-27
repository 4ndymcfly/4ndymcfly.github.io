# frozen_string_literal: true

source "https://rubygems.org"

gem "jekyll", "~> 4.0" # Jekyll principal, requerido para construir el sitio
gem "jekyll-theme-chirpy", "~> 7.0", ">= 7.0.1" # Tu tema actual

group :jekyll_plugins do
  gem "jekyll-compose" # Herramientas adicionales para posts
end

group :test do
  gem "html-proofer", "~> 5.0" # Validación de HTML
end

# Dependencias adicionales
gem "csv"     # Para manejo de datos CSV
gem "base64"  # Para codificación Base64

# Necesario en Ruby 3.0+ para evitar errores al usar Jekyll en Netlify
gem "webrick"
