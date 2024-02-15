# Schnitzeljagd
A map that with the right clues shows points on the map for some camps of the BWINF

How to add a new location:
1) copy the pfalz function and rename it
2) change the data json
  2.1) change the position
  2.2) remove all existing locations
  2.3) add as many locations as wished by 
    copy and pasting the output of create_location(answer, lat, lon, message)
    where "answer" is the clue the people should enter in the search field
    copy it into the array (and dont forget commas at the end)
3) add a Button
3.1) Add ```<a onclick="test()" class="button">Potenziell andere?</a>``` in the index.html
3.2) change name and called function
4) in app.js add your camp name and function to the switch statement like this:
  case "stingbert":
      stingbert()
