jQuery(function() {
  //initialise tab widget
  jQuery("#better-detection-tabs").tabs();

  //update error count
  function better_detection_error_count() {
    var trs = Math.max(0,jQuery("#better-detection-tabs-errors").find("tr").length-2);
    jQuery("#better-detection-error-count").html(" ("+trs+")");
  }
  better_detection_error_count();

  //handle button clicks
  jQuery("#better-detection-tabs-errors").on("click","input",function(e) {
    var data = {'action':'better_detection','mode':'unknown','key':ajax_object.key};
    var inp = jQuery(this);
    if(inp.hasClass("action-fixed")) {
      data.mode = "fixed";
      data.id = inp.attr("id").replace("action-fix-","");
    }
    if(inp.hasClass("action-ignore")) {
      data.mode = "ignore";
      data.id = inp.attr("id").replace("action-ign-","");
    }
    if(data.mode!=="unknown" && !isNaN(data.id)) {
      inp.after("<img src='"+ajax_object.gif+"' style='height:24px'>").hide().siblings("input").hide();
      jQuery.post(ajax_object.url, data, function(response) {
  			console.log(response);
        if(response==="Success") {
          inp.closest("tr").fadeOut("slow",function() { //remove row
            jQuery(this).remove();
            var trs = jQuery("#better-detection-tabs-errors").find("tr");
            if(trs.length===2) {
              jQuery("#better-detection-tabs-errors").html("<p>No new errors have been detected - yay!</p>"); //if only header/footer left then show message
            }
            better_detection_error_count();
          });
        }
        else {
          inp.siblings("img").remove(); //remove working image
          inp.siblings("input").addBack().show(); //restore buttons
        }
  		});
    }
  });
});
