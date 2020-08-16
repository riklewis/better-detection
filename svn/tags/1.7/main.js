jQuery(function() {
  //initialise tab widget
  jQuery("#better-detection-tabs").tabs({
    activate: function(event,ui) {
      var inp = jQuery("[name='_wp_http_referer']");
      var val = inp.val().split("#")[0];
      inp.val(val+"#"+ui.newPanel.attr("id"));
    }
  });

  //update error count
  function better_detection_error_count() {
    var trs = Math.max(0,jQuery("#better-detection-tabs-errors").find("tr").length-2);
    jQuery("#better-detection-error-count").html(" ("+trs+")");
  }
  better_detection_error_count();

  //handle button clicks
  jQuery("#better-detection-tabs").on("click","input",function(e) {
    var data = {'action':'better_detection','mode':'unknown','key':bsd_ajax_object.key};
    var inp = jQuery(this);
    if(inp.hasClass("action-fixed")) {
      data.mode = "fixed";
      data.id = inp.attr("id").replace("action-fix-","");
    }
    if(inp.hasClass("action-ignore")) {
      data.mode = "ignore";
      data.id = inp.attr("id").replace("action-ign-","");
    }
    if(inp.hasClass("action-test")) {
      data.val = inp.siblings("input").val();
      if(data.val) {
        data.mode = "test";
        data.id = inp.attr("id").replace("action-tst-","");
      }
    }
    if(data.mode!=="unknown") {
      inp.after("<img src='"+bsd_ajax_object.gif+"' class='better-detection-spinner'>").hide().siblings("input[type=button]").hide();
      jQuery.post(bsd_ajax_object.url, data, function(response) {
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
