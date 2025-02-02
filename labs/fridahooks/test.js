Java.perform(function() {
  var a = Java.use("Xl");
  a.f.implementation = function(a) {
    send("arg:", a)
    this.f(a)
  }
});
