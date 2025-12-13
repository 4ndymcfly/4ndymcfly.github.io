# 🎨 Componentes Personalizados - Hacking Épico

Esta guía explica cómo usar los componentes personalizados implementados en el blog.

## 📋 Tabla de Contenidos

1. [Badges de Dificultad](#badges-de-dificultad)
2. [Badges de Plataforma](#badges-de-plataforma)
3. [Machine Info Card](#machine-info-card)
4. [Tags con Iconos](#tags-con-iconos)
5. [Ejemplo Completo de WriteUp](#ejemplo-completo-de-writeup)

---

## 🎯 Badges de Dificultad

Muestra el nivel de dificultad con colores distintivos.

### Uso

```liquid
{% include difficulty-badge.html difficulty="Easy" %}
{% include difficulty-badge.html difficulty="Medium" %}
{% include difficulty-badge.html difficulty="Hard" %}
{% include difficulty-badge.html difficulty="Insane" %}
```

### Valores Válidos
- `Easy` - Verde
- `Medium` - Amarillo/Naranja
- `Hard` - Rojo
- `Insane` - Morado

---

## 🏷️ Badges de Plataforma

Identifica la plataforma de la máquina.

### Uso

```liquid
{% include platform-badge.html platform="HTB" %}
{% include platform-badge.html platform="THM" %}
{% include platform-badge.html platform="PG" %}
{% include platform-badge.html platform="VulnHub" %}
```

---

## 📊 Machine Info Card

Card completa con toda la información de la máquina.

### Uso Básico

```liquid
{% include machine-info.html 
  machine="Legacy"
  os="Windows"
  difficulty="Easy"
  platform="HTB"
  points="20"
  release="2017-03"
%}
```

### Parámetros

| Parámetro | Requerido | Descripción | Ejemplo |
|-----------|-----------|-------------|---------|
| `machine` | ✅ | Nombre de la máquina | "Legacy" |
| `os` | ✅ | Sistema operativo | "Windows", "Linux" |
| `difficulty` | ✅ | Nivel de dificultad | "Easy", "Medium", "Hard", "Insane" |
| `platform` | ✅ | Plataforma | "HTB", "THM", "PG", "VulnHub" |
| `points` | ❌ | Puntos obtenidos | "20", "30", "40" |
| `release` | ❌ | Fecha de lanzamiento | "2025-01", "2024-12" |

---

## 🏷️ Tags con Iconos

Los tags especiales mostrarán automáticamente iconos:

### Tags Soportados

En el front matter del post, usa estos tags y automáticamente tendrán iconos:

```yaml
tags: [linux, windows, web, active-directory, ad, oscp]
```

**Iconos automáticos:**
- `linux` → 🐧 Linux
- `windows` → 🪟 Windows
- `web` → 🌐 Web
- `active-directory` o `ad` → 📊 Active Directory
- `oscp` → 🔴 OSCP

---

## 📝 Ejemplo Completo de WriteUp

### Front Matter

```yaml
---
title: "Legacy - HackTheBox WriteUp"
date: 2025-01-15 10:00:00 +0100
categories: [WriteUps, HackTheBox]
tags: [windows, oscp, easy, smb, ms17-010]
image: /assets/img/cabeceras/2025-01-15-legacy-htb.png
---
```

### Contenido del Post

```markdown
# Legacy - HackTheBox WriteUp

{% include machine-info.html 
  machine="Legacy"
  os="Windows XP"
  difficulty="Easy"
  platform="HTB"
  points="20"
  release="2017-03"
%}

## Resumen

Legacy es una máquina Windows XP vulnerable a MS17-010 (EternalBlue). 
Esta máquina es perfecta para practicar explotación de vulnerabilidades SMB.

{% include difficulty-badge.html difficulty="Easy" %}
{% include platform-badge.html platform="HTB" %}

## Enumeración

### Nmap

\`\`\`bash
nmap -sC -sV -p- 10.10.10.4
\`\`\`

...resto del writeup...
```

---

## 🎨 Personalización de Certificaciones

Para modificar las certificaciones mostradas en el sidebar, edita:

**Archivo:** `_includes/sidebar.html`

**Líneas 44-50:**

```html
<div class="certifications-section">
  <h5>🎓 Certificaciones</h5>
  <div>
    <span class="cert-badge completed">eJPTv2</span>
    <span class="cert-badge in-progress">OSCP</span>
    <!-- Añade más certificaciones aquí -->
  </div>
</div>
```

**Clases disponibles:**
- `completed` - Certificación completada (borde verde)
- `in-progress` - En progreso (borde naranja)

---

## 📊 Personalización de Recursos en Footer

Para añadir/modificar recursos en el footer, edita:

**Archivo:** `_includes/footer.html`

**Sección:**

```html
<div class="footer-resources mb-4">
  <h5>🔗 Recursos Útiles</h5>
  <ul>
    <li><a href="URL" target="_blank" rel="noopener">Nombre</a></li>
    <!-- Añade más recursos aquí -->
  </ul>
</div>
```

---

## 🎨 Estilos CSS Personalizados

Todos los estilos están en: `assets/css/custom.scss`

Puedes modificar colores, tamaños y espaciados según tus preferencias.

---

## 📚 Más Información

Para más detalles sobre el tema Chirpy, visita:
- [Documentación Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy)
- [Jekyll Documentation](https://jekyllrb.com/docs/)

---

**Happy Hacking! 🚀**
