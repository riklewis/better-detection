jQuery(function() {
  //initialise tab widget
  jQuery("#better-detection-tabs").tabs();

  //update error count
  function better_detection_error_count() {
    var trs = jQuery("#better-detection-tabs-errors").find("tr").length-2;
    jQuery("#better-detection-error-count").html(" ("+trs+")");
  }
  better_detection_error_count();

  //handle button clicks
  jQuery("#better-detection-tabs-errors").on("click","input",function(e) {
    var inp = jQuery(this);
    if(inp.hasClass("action-fixed")) {

    }
    if(inp.hasClass("action-ignore")) {

    }
    better_detection_error_count();
  });
});
