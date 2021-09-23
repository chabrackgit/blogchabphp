const headerMobileButton = document.querySelector('.header-mobile-icon');
const headerMobileList = document.querySelector('.header-mobile-list');

console.log(headerMobileList);
console.log(headerMobileButton);
headerMobileButton.addEventListener('click', ()=> {
    headerMobileList.classList.toggle('show');
})