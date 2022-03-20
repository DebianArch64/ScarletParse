<script lang="ts">
  import { getInfo, save, MachoInfo, readableEntitlements } from "./lib/macho-parse"
  let files;
  var promise: Promise<MachoInfo> = Promise.resolve({
    commonName: "NULL",
    entitlements: "NULL",
    certificate: "NULL",
    icon: Promise.resolve(new Blob()),
    infoPlist: {},
  });

  const fileInput = (e) => {
    let file = e.target.files[0]
    promise = getInfo(file);
  }

</script>

<main>
  <h1>Import IPA/App Binary</h1>
  <input type="file" bind:files on:change={(e) => fileInput(e)}>
  {#if files && files[0]}
    {#await promise}
      <p>parsing app...</p>
    {:then info}
      {#await info.icon}
        <p>Loading Icon</p>
      {:then icon}
        <img src={URL.createObjectURL(icon)} alt="AppIcon"/>
      {/await}

      {#if info.infoPlist["CFBundleIdentifier"] != undefined}
        <p>Name: {info.infoPlist["CFBundleName"]}</p>
        <p>Version: {info.infoPlist["CFBundleVersion"]}</p>
        <p>BundleID: {info.infoPlist["CFBundleIdentifier"]}</p>
      {/if}
      
      <!-- {#each readableEntitlements(info.entitlements) as feature}
        <p>{feature}</p>
      {/each} -->
      <p>{info.commonName}</p>
      <button on:click={() => save("cert.pem", info.certificate)}>Download Certificate</button>
      <button on:click={() => save("entitlements.xml", info.entitlements)}>Download Entitlements</button>
      
    {/await}
  {/if}
</main>

<style>
  :root {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen,
      Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
  }

  main {
    text-align: center;
    padding: 1em;
    margin: 0 auto;
  }
</style>
