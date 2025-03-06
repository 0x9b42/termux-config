function tes() {
    console.log("this sebelum dioverride", this)
    this = 0;
    console.log("this setelah dioverride", this)
}

tes()
