document.addEventListener("DOMContentLoaded" ,() => {
    const loginform=document.querySelector("#login");
    const createaccountform=document.querySelector("#createaccount");

    document.querySelector("#linkCreateAccount").addEventListener("click", e =>{
        e.preventDefault();
        loginform.classList.add("form-hidden");
        createaccountform.classList.remove("form-hidden");
    });

    document.querySelector("#linkLogin").addEventListener("click", e =>{
        e.preventDefault();
        loginform.classList.remove("form-hidden");
        createaccountform.classList.add("form-hidden");
    });

});
