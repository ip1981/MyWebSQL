(function(d){d.fn.__bind__=d.fn.bind;d.fn.__unbind__=d.fn.unbind;d.fn.__find__=d.fn.find;var c={version:"0.7.9",override:/keypress|keydown|keyup/g,suspended:!1,triggersMap:{},specialKeys:{27:"esc",9:"tab",32:"space",13:"return",8:"backspace",145:"scroll",20:"capslock",144:"numlock",19:"pause",45:"insert",36:"home",46:"del",35:"end",33:"pageup",34:"pagedown",37:"left",38:"up",39:"right",40:"down",109:"-",112:"f1",113:"f2",114:"f3",115:"f4",116:"f5",117:"f6",118:"f7",119:"f8",120:"f9",121:"f10",122:"f11",
123:"f12",191:"/"},shiftNums:{"`":"~",1:"!",2:"@",3:"#",4:"$",5:"%",6:"^",7:"&",8:"*",9:"(","0":")","-":"_","=":"+",";":":","'":'"',",":"<",".":">","/":"?","\\":"|"},newTrigger:function(b,c,d){var a={};a[b]={};a[b][c]={cb:d,disableInInput:!1};return a}};c.specialKeys=d.extend(c.specialKeys,{96:"0",97:"1",98:"2",99:"3",100:"4",101:"5",102:"6",103:"7",104:"8",105:"9",106:"*",107:"+",109:"-",110:".",111:"/"});d.fn.find=function(b){this.query=b;return d.fn.__find__.apply(this,arguments)};d.fn.unbind=
function(b,e,k){d.isFunction(e)&&(k=e,e=null);if(e&&"string"===typeof e)for(var a=(this.prevObject&&this.prevObject.query||this[0].id&&this[0].id||this[0]).toString(),f=b.split(" "),g=0;g<f.length;g++)delete c.triggersMap[a][f[g]][e];return this.__unbind__(b,k)};d.fn.bind=function(b,e,k){var a=b.match(c.override);if(d.isFunction(e)||!a||null==e)return this.__bind__.apply(this,arguments);var f=null,g=d.trim(b.replace(c.override,""));g&&(f=this.__bind__(g,e,k));"string"===typeof e&&(e={combi:e});if(e.combi)for(g=
0;g<a.length;g++){var f=a[g],h=e.combi.toLowerCase(),m=c.newTrigger(f,h,k),j=(this.prevObject&&this.prevObject.query||this[0].id&&this[0].id||this[0]).toString();m[f][h].disableInInput=e.disableInInput;c.triggersMap[j]?c.triggersMap[j][f]||(c.triggersMap[j][f]=m[f]):c.triggersMap[j]=m;var n=c.triggersMap[j][f][h];n?n.constructor!==Array?c.triggersMap[j][f][h]=[n]:c.triggersMap[j][f][h][n.length]=m[f][h]:c.triggersMap[j][f][h]=[m[f][h]];this.each(function(){var a=d(this);a.attr("hkId")&&a.attr("hkId")!==
j&&(j=a.attr("hkId")+";"+j);a.attr("hkId",j)});f=this.__bind__(a.join(" "),e,c.handler)}return f};c.findElement=function(b){if(!d(b).attr("hkId")&&(d.browser.opera||d.browser.safari))for(;!d(b).attr("hkId")&&b.parentNode;)b=b.parentNode;return b};c.suspend=function(b){this.suspended=b;return this};c.handler=function(b){var e=c.findElement(b.currentTarget),e=d(e),k=e.attr("hkId");if(k){for(var k=k.split(";"),a=b.which,f=b.type,g=c.specialKeys[a],h=!g&&String.fromCharCode(a).toLowerCase(),m=b.shiftKey,
j=b.ctrlKey,n=b.altKey||b.originalEvent.altKey,l=null,a=0;a<k.length;a++)if(c.triggersMap[k[a]][f]){l=c.triggersMap[k[a]][f];break}if(l&&(!m&&!j&&!n?g=l[g]||h&&l[h]:(a="",n&&(a+="alt+"),j&&(a+="ctrl+"),m&&(a+="shift+"),(g=l[a+g])||h&&(g=l[a+h]||l[a+c.shiftNums[h]]||"shift+"===a&&l[c.shiftNums[h]])),g)){h=!1;for(a=0;a<g.length;a++){if(g[a].disableInInput&&(l=d(b.target),e.is("input")||e.is("textarea")||e.is("select")||l.is("input")||l.is("textarea")||l.is("select")))return!0;c.suspended||(h=h||g[a].cb.apply(this,
[b]))}return h}}};window.hotkeys=c;return d})(jQuery);