
# Capture Page Cisco U


```js
const lesson = document.querySelector('#scrollback-target');

if (!lesson) {
  console.error('scrollback-target not found');
} else {
  // Unlock the lesson itself
  lesson.style.setProperty('height', 'auto', 'important');
  lesson.style.setProperty('max-height', 'none', 'important');
  lesson.style.setProperty('overflow', 'visible', 'important');
  lesson.style.setProperty('overflow-y', 'visible', 'important');
  lesson.style.setProperty('width', '100%', 'important');
  lesson.style.setProperty('max-width', 'none', 'important');

  // Unlock ONLY height/overflow of its ancestors.
  // Do NOT touch position/display.
  let p = lesson.parentElement;

  while (p && p !== document.body) {
    p.style.setProperty('height', 'auto', 'important');
    p.style.setProperty('max-height', 'none', 'important');
    p.style.setProperty('overflow-y', 'visible', 'important');
    p.style.setProperty('overflow', 'visible', 'important');

    p = p.parentElement;
  }

  document.documentElement.style.setProperty('height', 'auto', 'important');
  document.documentElement.style.setProperty('overflow-y', 'auto', 'important');

  document.body.style.setProperty('height', 'auto', 'important');
  document.body.style.setProperty('overflow-y', 'auto', 'important');

  console.log('Lesson unlocked without changing layout positioning.');
}
```