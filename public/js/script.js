document.addEventListener('DOMContentLoaded', () => {
    const allButtons = document.querySelectorAll('.searchBtn');
    const searchBar = document.querySelector('.searchBar');
    const searchInput = document.querySelector('#searchInput');
    const searchClose = document.querySelector('#searchClose');

    allButtons.forEach((btn) => {
        btn.addEventListener('click', function() {
            searchBar.style.visibility = 'visible';
            searchBar.classList.add('open');
            this.setAttribute('aria-expanded', 'true');
            searchInput.focus();
        })
    })

    searchClose.addEventListener('click', () => {
        searchBar.classList.remove('open');
        searchBar.style.visibility = 'hidden';
    })
})