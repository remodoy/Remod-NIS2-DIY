---
layout: default
title: Ohjeet
permalink: /ohjeet/
---

# {{ page.title }}

<ul>
  {% for page in site.pages %}
    {% if page.path contains 'ohjeet/' and page.name != 'index.md' %}
      <li><a href="{{ page.path | replace: '.md', '.html' | relative_url }}">{{ page.title }}</a></li>
    {% endif %}
  {% endfor %}
</ul>