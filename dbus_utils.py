brew_coffee:
  name: Koffie zetten
  description: Zet een drankje met je Melitta koffiezetapparaat
  fields:
    entity_id:
      name: Apparaat
      description: Het koffiezetapparaat entity ID
      required: true
      selector:
        entity:
          integration: melitta_coffee
    beverage:
      name: Drankje
      description: Het type drankje om te zetten
      required: false
      default: espresso
      selector:
        select:
          options:
            - label: Espresso
              value: espresso
            - label: Ristretto
              value: ristretto
            - label: Lungo
              value: lungo
            - label: Dubbele Espresso
              value: espresso_doppio
            - label: "Caf\u00e9 Cr\u00e8me"
              value: cafe_creme
            - label: Cappuccino
              value: cappuccino
            - label: "Caff\u00e8 Latte"
              value: caffe_latte
            - label: Latte Macchiato
              value: latte_macchiato
            - label: Flat White
              value: flat_white
            - label: Americano
              value: americano
            - label: Espresso Macchiato
              value: espresso_macchiato
            - label: "Caf\u00e9 au Lait"
              value: cafe_au_lait
            - label: Warme Melk
              value: milk
            - label: Melkschuim
              value: milk_froth
            - label: Heet Water
              value: hot_water
    strength:
      name: Sterkte
      description: De sterkte van de koffie
      required: false
      default: medium
      selector:
        select:
          options:
            - label: Heel Mild
              value: very_mild
            - label: Mild
              value: mild
            - label: Normaal
              value: medium
            - label: Sterk
              value: strong
            - label: Extra Sterk
              value: very_strong
    cups:
      name: Kopjes
      description: Aantal kopjes
      required: false
      default: 1
      selector:
        number:
          min: 1
          max: 4
          step: 1
