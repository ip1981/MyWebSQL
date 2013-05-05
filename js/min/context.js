var _contextMenu=null;
(function(c){c.contextMenu={shadow:!1,shadowOffset:0,shadowOffsetX:5,shadowOffsetY:5,shadowWidthAdjust:-3,shadowHeightAdjust:-3,shadowOpacity:0.2,shadowClass:"context-menu-shadow",shadowColor:"black",offsetX:0,offsetY:0,appendTo:"body",direction:"down",constrainToScreen:!0,showTransition:"show",hideTransition:"hide",showSpeed:null,hideSpeed:null,showCallback:null,hideCallback:null,className:"context-menu",itemClassName:"context-menu-item",itemHoverClassName:"context-menu-item-hover",disabledItemClassName:"context-menu-item-disabled",
disabledItemHoverClassName:"context-menu-item-disabled-hover",separatorClassName:"context-menu-separator",innerDivClassName:"context-menu-item-inner",themePrefix:"context-menu-theme-",theme:"default",separator:"context-menu-separator",target:null,menu:null,shadowObj:null,bgiframe:null,shown:!1,useIframe:!1,create:function(b,d){var a=c.extend({},this,d);"string"==typeof b?a.menu=c(b):"function"==typeof b?a.menuFunction=b:a.menu=a.createMenu(b,a);a.menu&&(a.menu.css({display:"none"}),c(a.appendTo).append(a.menu));
a.shadow&&(a.createShadow(a),a.shadowOffset&&(a.shadowOffsetX=a.shadowOffsetY=a.shadowOffset));c("body").bind("contextmenu",function(){a.hide()});return a},createIframe:function(){return c('<iframe frameborder="0" tabindex="-1" src="javascript:false" style="display:block;position:absolute;z-index:-1;filter:Alpha(Opacity=0);"/>')},createMenu:function(b,d){var a=d.className;c.each(d.theme.split(","),function(b,c){a+=" "+d.themePrefix+c});for(var e=c("<table cellspacing=0 cellpadding=0></table>").click(function(){d.hide();
return!1}),f=c("<tr></tr>"),g=c("<td></td>"),h=c('<div class="'+a+'"></div>'),j=0;j<b.length;j++)if(b[j]==c.contextMenu.separator)h.append(d.createSeparator());else for(var k in b[j])h.append(d.createMenuItem(k,b[j][k]));d.useIframe&&g.append(d.createIframe());e.append(f.append(g.append(h)));return e},createMenuItem:function(b,d){var a=this;"function"==typeof d&&(d={onclick:d});var e=c.extend({onclick:function(){},className:"",hoverClassName:a.itemHoverClassName,icon:"",disabled:!1,title:"",hoverItem:a.hoverItem,
hoverItemOut:a.hoverItemOut},d),f=e.icon?"background-image:url("+e.icon+");":"",g=c('<div class="'+a.itemClassName+" "+e.className+(e.disabled?" "+a.disabledItemClassName:"")+'" title="'+e.title+'"></div>').click(function(b){return a.isItemDisabled(this)?!1:e.onclick.call(a.target,this,a,b)}).hover(function(){e.hoverItem.call(this,a.isItemDisabled(this)?a.disabledItemHoverClassName:e.hoverClassName)},function(){e.hoverItemOut.call(this,a.isItemDisabled(this)?a.disabledItemHoverClassName:e.hoverClassName)}),
f=c('<div class="'+a.innerDivClassName+'" style="'+f+'">'+b+"</div>");g.append(f);return g},createSeparator:function(){return c('<div class="'+this.separatorClassName+'"></div>')},isItemDisabled:function(b){return c(b).is("."+this.disabledItemClassName)},hoverItem:function(b){c(this).addClass(b)},hoverItemOut:function(b){c(this).removeClass(b)},createShadow:function(b){b.shadowObj=c('<div class="'+b.shadowClass+'"></div>').css({display:"none",position:"absolute",zIndex:9998,opacity:b.shadowOpacity,
backgroundColor:b.shadowColor});c(b.appendTo).append(b.shadowObj)},showShadow:function(b,c){if(this.shadow)this.shadowObj.css({width:this.menu.width()+this.shadowWidthAdjust+"px",height:this.menu.height()+this.shadowHeightAdjust+"px",top:c+this.shadowOffsetY+"px",left:b+this.shadowOffsetX+"px"}).addClass(this.shadowClass)[this.showTransition](this.showSpeed)},beforeShow:function(){return!0},show:function(b,d){var a=this,e=d.pageX,f=d.pageY;_contextMenu=this;a.target=b;if(!1!==a.beforeShow()){if(a.menuFunction){a.menu&&
c(a.menu).remove();a.menu=a.menuFunction(a,b,d);if(!a.menu)return!1;a.menu.css({display:"none"});c(a.appendTo).append(a.menu)}var g=a.menu;a.menu.find("a").unbind("click").click(function(a){otarget=d.originalTarget||d.target;a.preventDefault();name=(p=c(otarget).attr("data-parent"))?p+"."+c(otarget).text().replace('"',"&qout;"):c(otarget).text().replace('"',"&qout;");tempFn=c(this).attr("href").replace("[name]",'"'+name+'"');eval(tempFn)});e+=a.offsetX;f+=a.offsetY;e=a.getPosition(e,f,a,d);a.showShadow(e.x,
e.y,d);a.useIframe&&g.find("iframe").css({width:g.width()+a.shadowOffsetX+a.shadowWidthAdjust,height:g.height()+a.shadowOffsetY+a.shadowHeightAdjust});g.css({top:e.y+"px",left:e.x+"px",position:"absolute",zIndex:99999})[a.showTransition](a.showSpeed,a.showCallback?function(){a.showCallback.call(a)}:null);a.shown=!0;c(document).one("click",null,function(){a.hide()})}},getPosition:function(b,d,a){b+=a.offsetX;d+=a.offsetY;var e=c(a.menu).height(),f=c(a.menu).width(),g=a.direction;if(a.constrainToScreen){var h=
c(window),j=h.height();a=h.width();"down"==g&&d+e-h.scrollTop()>j&&(g="up");f=b+f-h.scrollLeft();f>a&&(b-=f-a)}"up"==g&&(d-=e);return{x:b,y:d}},hide:function(){var b=this;if(b.shown){b.iframe&&c(b.iframe).hide();if(b.menu)b.menu[b.hideTransition](b.hideSpeed,b.hideCallback?function(){b.hideCallback.call(b)}:null);if(b.shadow)b.shadowObj[b.hideTransition](b.hideSpeed)}b.shown=!1;_contextMenu=null}};c.fn.contextMenu=function(b,d){var a=c.contextMenu.create(b,d);return this.each(function(){c(this).bind("contextmenu",
function(b){a.show(this,b);return!1})})}})(jQuery);