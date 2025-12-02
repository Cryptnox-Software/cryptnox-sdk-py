// Custom JavaScript for the documentation

// Add any custom JavaScript functionality here
console.log('Cryptnox SDK Documentation loaded');

// Example: Smooth scrolling for anchor links
document.addEventListener('DOMContentLoaded', function() {
    // Get all anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    
    anchorLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            
            // Skip if it's just "#"
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                e.preventDefault();
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
                
                // Update URL without jumping
                history.pushState(null, null, targetId);
            }
        });
    });
    
    // Add copy button to code blocks
    const codeBlocks = document.querySelectorAll('.highlight pre');
    
    codeBlocks.forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.textContent = 'Copy';
        button.style.cssText = 'position: absolute; right: 5px; top: 5px; padding: 2px 8px; font-size: 12px; cursor: pointer;';
        
        const wrapper = block.parentElement;
        wrapper.style.position = 'relative';
        wrapper.appendChild(button);
        
        button.addEventListener('click', function() {
            const code = block.textContent;
            navigator.clipboard.writeText(code).then(() => {
                button.textContent = 'Copied!';
                setTimeout(() => {
                    button.textContent = 'Copy';
                }, 2000);
            });
        });
    });
});

