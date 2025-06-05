// Utility functions module
// Exports: waitForOpenPGP

export function waitForOpenPGP() {
    return new Promise((resolve, reject) => {
        let attempts = 0;
        const maxAttempts = 50;
        function check() {
            attempts++;
            if (typeof openpgp !== 'undefined') {
                resolve();
            } else if (attempts >= maxAttempts) {
                console.error('OpenPGP failed to load after 5 seconds using the current CDN.');
                reject(new Error('OpenPGP library failed to load. Check CDN link and network.'));
            } else {
                setTimeout(check, 100);
            }
        }
        check();
    });
} 