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
    var data = {'action':'better_detection','mode':'unknown','key':ajax_object.key};
    if(inp.hasClass("action-fixed")) {
      data.mode = "fixed";
    }
    if(inp.hasClass("action-ignore")) {
      data.mode = "ignore";
    }
    jQuery.post(ajax_object.url, data, function(response) {
			alert('Got this from the server: ' + response);
      //// TODO: Remove row if successful
      better_detection_error_count();
		});
  });
});
