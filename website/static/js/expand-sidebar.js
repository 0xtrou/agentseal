// Auto-expand all sidebar categories on load
document.addEventListener('DOMContentLoaded', function() {
  // Wait a bit for React to hydrate
  setTimeout(function() {
    // Find all collapsed category buttons
    const collapsedButtons = document.querySelectorAll('button.menu__caret');
    
    // Click each collapsed button to expand it
    collapsedButtons.forEach(function(button) {
      const parent = button.closest('.menu__list-item');
      if (parent && !parent.classList.contains('menu__list-item--collapsed')) {
        // Already expanded, skip
        return;
      }
      // Click to expand
      button.click();
    });
  }, 100);
});