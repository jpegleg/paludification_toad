resource "vultr_ssh_key" "enre" {
  name = "enre"
  ssh_key = "YOUR PUBLIC KEY GOES HERE"
}

resource "vultr_instance" "gtd1" {
    hostname = "gtd1"
    plan = "vc2-1c-1gb"
    region = "atl"
    os_id = 2772
    ssh_key_ids = ["${vultr_ssh_key.enre.id}"]
    label = "gtd1"
}
