 document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Header background on scroll
window.addEventListener('scroll', () => {
    const header = document.querySelector('header');
    if (window.scrollY > 100) {
        header.style.background = 'rgba(15, 15, 35, 0.98)';
    } else {
        header.style.background = 'rgba(15, 15, 35, 0.95)';
    }
});

// Scroll reveal animation
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('revealed');
        }
    });
}, observerOptions);

document.querySelectorAll('.scroll-reveal').forEach(el => {
    observer.observe(el);
});

// Dynamic typing effect for hero section
function typeWriter(element, text, speed = 100) {
    let i = 0;
    element.innerHTML = '';
    
    function type() {
        if (i < text.length) {
            element.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, speed);
        }
    }
    type();
}

// Initialize typing effect after page load
window.addEventListener('load', () => {
    const heroTitle = document.querySelector('.hero h1');
    const originalText = heroTitle.textContent;
    setTimeout(() => {
        typeWriter(heroTitle, originalText, 80);
    }, 500);
});

// Interactive code block
document.addEventListener('DOMContentLoaded', () => {
    const codeBlock = document.querySelector('.code-content');
    if (codeBlock) {
        codeBlock.addEventListener('mouseenter', () => {
            codeBlock.style.transform = 'scale(1.02)';
            codeBlock.style.transition = 'transform 0.3s ease';
        });
        
        codeBlock.addEventListener('mouseleave', () => {
            codeBlock.style.transform = 'scale(1)';
        });
    }
});

// Parallax effect for animated background
window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    const rate = scrolled * -0.5;
    const animatedBg = document.querySelector('.animated-bg');
    if (animatedBg) {
        animatedBg.style.transform = `translateY(${rate}px)`;
    }
});

// Add sparkle effect to feature cards
document.querySelectorAll('.feature-card').forEach(card => {
    card.addEventListener('mouseenter', () => {
        card.style.boxShadow = '0 20px 40px rgba(99, 102, 241, 0.2)';
        card.style.transform = 'translateY(-10px) scale(1.02)';
    });
    
    card.addEventListener('mouseleave', () => {
        card.style.boxShadow = 'none';
        card.style.transform = 'translateY(0) scale(1)';
    });
});
