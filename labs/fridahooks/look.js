Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
    console.log("[*] Starting activity:", intent.getComponent().getClassName());
    this.startActivity(intent);
  };
});

Java.enumerateLoadedClasses({
  onMatch: function(className) {
    if (className.includes("module_home")) {
      console.log("[*] Loaded class:", className);
    }
  },
  onComplete: function() {}
});
