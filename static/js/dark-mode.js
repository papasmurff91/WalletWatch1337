/**
 * Dark mode functionality for Solana Wallet Monitor
 */

// Check for saved theme preference or use the system preference
const getThemePreference = () => {
    // Check if user has previously chosen a theme
    if (localStorage.getItem('theme')) {
        return localStorage.getItem('theme');
    }
    
    // Otherwise, check if system prefers dark mode
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark';
    }
    
    // Default to light mode
    return 'light';
};

// Apply theme to HTML element
const applyTheme = (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
    
    // Update toggle button text and icon
    const toggleButton = document.getElementById('darkModeToggle');
    if (toggleButton) {
        // Find the icon and change it
        const icon = toggleButton.querySelector('i');
        if (icon) {
            // Clear the existing icon classes
            icon.setAttribute('data-feather', theme === 'dark' ? 'sun' : 'moon');
            
            // If feather is available, replace icons
            if (typeof feather !== 'undefined') {
                feather.replace();
            }
        }
        
        // Update the text
        const text = toggleButton.querySelector('span');
        if (text) {
            text.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
        }
    }
    
    // Store the preference
    localStorage.setItem('theme', theme);
};

// Toggle between dark and light mode
const toggleDarkMode = () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(newTheme);
};

// Initialize theme when document is ready
document.addEventListener('DOMContentLoaded', () => {
    // Set the initial theme
    const theme = getThemePreference();
    applyTheme(theme);
    
    // Add event listener to toggle button if it exists
    const toggleButton = document.getElementById('darkModeToggle');
    if (toggleButton) {
        toggleButton.addEventListener('click', toggleDarkMode);
    }
});