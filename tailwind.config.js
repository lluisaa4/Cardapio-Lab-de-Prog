/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html","./js/**/*.js"],
  theme: {
    fontFamily: {
      'sans': ['Roboto','sans-serif']
    },
    extend: {
      backgroundImage: {
        home: "url('/assets/bg.png')"
      }
    }
  },
  plugins: [],
}
