---
layout: default
title: Materiaalit
permalink: /materiaalit/
---

# {{ page.title }}

<ul>
  {% for file in site.static_files %}
    {% if file.path contains '/materiaalit/' and file.name != 'index.md' %}
      <li><a href="{{ file.path | replace: '.md', '.html' | relative_url }}">{{ file.path | remove_first: '/materiaalit/' }}</a></li>
    {% endif %}
  {% endfor %}
</ul>
