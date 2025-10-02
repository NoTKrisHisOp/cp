# AGENTS.md - Campus Hire Dashboard

## Project Overview
Single-page HTML application for campus placement preparation with dashboard UI, dark mode, and progress tracking.

## Structure
- `dashboard.html` - Main application file containing all HTML, CSS, and JavaScript

## Commands
No build process needed - open `dashboard.html` directly in browser for testing.

## Code Style
- **HTML**: HTML5 with semantic elements
- **CSS**: Inline `<style>` block, BEM-like naming (kebab-case for classes)
- **JavaScript**: Vanilla ES6+ in inline `<script>` tag
- **Formatting**: Indentation with 2 spaces, compact style
- **Naming**: Descriptive IDs (camelCase for JS variables/functions, kebab-case for CSS classes)
- **Colors**: Gradient-based design (`linear-gradient` with blues/purples: `#4f46e5`, `#3b82f6`, `#9333ea`, `#06b6d4`)
- **Effects**: Heavy use of `backdrop-filter: blur()`, `box-shadow`, transitions (0.3s-0.5s ease), hover transforms
- **Dark Mode**: `.dark` class toggle on `<body>` with alternative color scheme

## Key Features
- Fixed header (70px) with logo and actions
- Fixed sidebar (220px wide) with nav items
- Responsive grid layout for cards (`repeat(auto-fit, minmax(250px, 1fr))`)
- Progress bar animation system
- Mobile responsive (sidebar collapses < 768px)
